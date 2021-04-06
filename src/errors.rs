use casbin::error::AdapterError;
use casbin::Error as CasbinError;

pub struct ParsePolicyFailed(pub String);

impl From<ParsePolicyFailed> for CasbinError {
    fn from(e: ParsePolicyFailed) -> Self {
        CasbinError::AdapterError(AdapterError(Box::new(e)))
    }
}

impl std::fmt::Debug for ParsePolicyFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("can not parse policies: {}", self.0))
    }
}

impl std::fmt::Display for ParsePolicyFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("can not parse policies: {}", self.0))
    }
}

impl std::error::Error for ParsePolicyFailed {}
