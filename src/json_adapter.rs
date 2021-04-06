use crate::{models::Policies, ParsePolicyFailed};
use async_trait::async_trait;
use casbin::{error::AdapterError, Adapter, Error, Filter, Model, Result};

#[cfg(feature = "runtime-async-std")]
use async_std::{
    fs::File,
    io::prelude::*,
    io::{Error as IoError, ErrorKind},
    path::Path,
};

#[cfg(feature = "runtime-tokio")]
use std::{
    io::{Error as IoError, ErrorKind},
    path::Path,
};
#[cfg(feature = "runtime-tokio")]
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncWriteExt},
};

pub struct JsonAdapter<P> {
    file_path: P,
    is_filtered: bool,
}

#[async_trait]
impl<P> Adapter for JsonAdapter<P>
where
    P: AsRef<Path> + Send + Sync,
{
    async fn load_policy(&self, m: &mut dyn Model) -> Result<()> {
        self.load_filtered_policy_into_model(
            m,
            Filter {
                p: Vec::new(),
                g: Vec::new(),
            },
        )
        .await?;
        Ok(())
    }

    async fn load_filtered_policy<'a>(&mut self, m: &mut dyn Model, f: Filter<'a>) -> Result<()> {
        self.is_filtered = self.load_filtered_policy_into_model(m, f).await?;
        Ok(())
    }

    async fn save_policy(&mut self, m: &mut dyn Model) -> Result<()> {
        if self.file_path.as_ref().as_os_str().is_empty() {
            return Err(
                IoError::new(ErrorKind::Other, "save policy failed, file path is empty").into(),
            );
        }

        let mut policies = Policies::new();
        for sec in vec!["p", "g"] {
            if let Some(ast_map) = m.get_model().get(sec) {
                for (ptype, ast) in ast_map {
                    let ps = ast
                        .get_policy()
                        .iter()
                        .map(|v| v.iter().map(|s| s.clone()).collect())
                        .collect();
                    policies.0.insert(ptype.to_string(), ps);
                }
            }
        }

        self.save_policy_to_file(&policies).await?;
        Ok(())
    }

    async fn clear_policy(&mut self) -> Result<()> {
        self.save_policy_to_file(&Policies::new()).await?;
        Ok(())
    }

    async fn add_policies(
        &mut self,
        _sec: &str,
        ptype: &str,
        rules: Vec<Vec<String>>,
    ) -> Result<bool> {
        let mut json = self.load_json().await?;
        match json.0.get_mut(ptype) {
            Some(v) => {
                for rule in &rules {
                    if v.contains(rule) {
                        return Ok(false);
                    }
                }
                v.extend(rules);
            }
            None => {
                json.0.insert(ptype.to_string(), rules);
            }
        }
        self.save_policy_to_file(&json).await?;
        Ok(true)
    }

    async fn add_policy(&mut self, _sec: &str, ptype: &str, rule: Vec<String>) -> Result<bool> {
        let mut json = self.load_json().await?;
        match json.0.get_mut(ptype) {
            Some(v) => {
                if !v.contains(&rule) {
                    v.push(rule);
                } else {
                    return Ok(false);
                }
            }
            None => {
                json.0.insert(ptype.to_string(), vec![rule]);
            }
        }

        self.save_policy_to_file(&json).await?;
        Ok(true)
    }

    fn is_filtered(&self) -> bool {
        self.is_filtered
    }

    async fn remove_filtered_policy(
        &mut self,
        _sec: &str,
        ptype: &str,
        field_index: usize,
        field_values: Vec<String>,
    ) -> Result<bool> {
        if field_values.is_empty() {
            return Ok(false);
        }
        let mut json = self.load_json().await?;
        let mut temp = Vec::new();
        match json.0.remove(ptype) {
            Some(v) => {
                for rule in v {
                    for (i, field_value) in field_values.iter().enumerate() {
                        if field_index + i >= rule.len() {
                            return Ok(false);
                        }
                        if !field_value.is_empty() && &rule[field_index + i] != field_value {
                            temp.push(rule.clone());
                            break;
                        }
                    }
                }
            }
            None => {}
        }
        json.0.insert(ptype.to_string(), temp);
        self.save_policy_to_file(&json).await?;
        Ok(true)
    }

    async fn remove_policies(
        &mut self,
        _sec: &str,
        ptype: &str,
        rules: Vec<Vec<String>>,
    ) -> Result<bool> {
        let mut json = self.load_json().await?;
        match json.0.remove(ptype) {
            Some(mut v) => {
                for rule in &rules {
                    if !v.contains(rule) {
                        return Ok(false);
                    }
                }
                for rule in &rules {
                    v = v.into_iter().filter(|r| r != rule).collect();
                }
                json.0.insert(ptype.to_string(), v);
            }
            None => {
                return Ok(true);
            }
        }
        self.save_policy_to_file(&json).await?;
        Ok(true)
    }

    async fn remove_policy(&mut self, _sec: &str, ptype: &str, rule: Vec<String>) -> Result<bool> {
        let mut json = self.load_json().await?;
        let mut removed = false;
        match json.0.remove(ptype) {
            Some(v) => {
                let v = v
                    .into_iter()
                    .filter(|v| {
                        if v == &rule {
                            removed = true;
                            true
                        } else {
                            false
                        }
                    })
                    .collect::<Vec<Vec<String>>>();
                json.0.insert(ptype.to_string(), v);
            }
            None => return Ok(false),
        }
        self.save_policy_to_file(&json).await?;
        Ok(removed)
    }
}

impl<P> JsonAdapter<P>
where
    P: AsRef<Path> + Send + Sync,
{
    pub fn new(p: P) -> JsonAdapter<P> {
        JsonAdapter {
            file_path: p,
            is_filtered: false,
        }
    }

    async fn save_policy_to_file(&self, p: &Policies) -> Result<()> {
        let buf = match serde_json::to_vec(p) {
            Ok(s) => s,
            Err(e) => {
                return Err(Error::AdapterError(AdapterError(Box::new(e))));
            }
        };

        let mut file = File::create(&self.file_path).await?;
        file.write_all(&buf).await?;
        Ok(())
    }

    async fn load_json(&self) -> Result<Policies> {
        let mut fd = File::open(&self.file_path).await?;
        let mut buf = String::new();
        fd.read_to_string(&mut buf).await?;
        let policies: Policies = match serde_json::from_str(&buf) {
            Ok(p) => p,
            Err(e) => return Err(Error::AdapterError(AdapterError(Box::new(e)))),
        };
        Ok(policies)
    }

    async fn load_filtered_policy_into_model<'a>(
        &self,
        m: &mut dyn Model,
        f: Filter<'a>,
    ) -> Result<bool> {
        let json = self.load_json().await?;
        println!("{:?}", json);
        let mut filtered = false;
        for (ptype, polices) in json.0 {
            let sec = ptype
                .chars()
                .next()
                .map(|x| x.to_string())
                .ok_or(ParsePolicyFailed("ptype should be string".to_string()))?;

            let f = if sec == "p" { &f.p } else { &f.g };
            'outer: for policy in polices {
                for (i, rule) in f.iter().enumerate() {
                    if !rule.is_empty() && rule != &policy[i] {
                        filtered = true;
                        continue 'outer;
                    }
                }
                m.add_policy(&sec, &ptype, policy);
            }
        }
        Ok(filtered)
    }
}

