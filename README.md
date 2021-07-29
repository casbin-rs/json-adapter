# json-adapter

[![CI](https://github.com/casbin-rs/json-adapter/actions/workflows/ci.yml/badge.svg)](https://github.com/casbin-rs/json-adapter/actions)
[![codecov](https://codecov.io/gh/casbin-rs/json-adapter/branch/master/graph/badge.svg)](https://codecov.io/gh/casbin-rs/json-adapter)

Json Adapter is a [json](https://github.com/serde-rs/json) adapter for [Casbin-rs](https://github.com/casbin/casbin-rs). With this library, Casbin can load policy from json format file or save policy into it with fully asynchronous support.

## Dependency

Add following to `Cargo.toml`

```
json-adapter = { version = "0.1.0", features = "runtime-async-std" }
async-std = "1.6.4"
```

for using `tokio`

```
json-adapter = { version = "0.1.0", features = "runtime-tokio" }
tokio = "1.2.0"
```

## Examples

```
let adapter = JsonAdapter::new("examples/rbac_policy.json");
let e = Enforcer::new(m, adapter).await.unwrap();
```

for policy file configuration, please refer to [example](./examples)


