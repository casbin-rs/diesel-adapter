# diesel-adapter

[![Crates.io](https://img.shields.io/crates/v/diesel-adapter.svg)](https://crates.io/crates/diesel-adapter)
[![Docs](https://docs.rs/diesel-adapter/badge.svg)](https://docs.rs/diesel-adapter)
[![CI](https://github.com/casbin-rs/diesel-adapter/workflows/CI/badge.svg)](https://github.com/casbin-rs/diesel-adapter/actions)
[![codecov](https://codecov.io/gh/casbin-rs/diesel-adapter/branch/master/graph/badge.svg)](https://codecov.io/gh/casbin-rs/diesel-adapter)

Diesel Adapter is the [Diesel](https://github.com/diesel-rs/diesel) adapter for [Casbin-rs](https://github.com/casbin/casbin-rs). With this library, Casbin can load policy from Diesel supported database or save policy to it.

Based on [Diesel](https://github.com/diesel-rs/diesel), The current supported databases are:

- [Mysql](https://www.mysql.com/)
- [Postgres](https://github.com/lib/pq)


## Install

Add it to `Cargo.toml`

```
diesel-adapter = { version = "0.8.2", features = ["postgres"] }
async-std = "1.8.0"
```

## Example

```rust
use diesel_adapter::casbin::prelude::*;
use diesel_adapter::DieselAdapter;

#[async_std::main]
async fn main() -> Result<()> {
    let mut m = DefaultModel::from_file("examples/rbac_model.conf").await?;
    let a = DieselAdapter::new("postgres://casbin_rs:casbin_rs@127.0.0.1:5432/casbin", 8)?;
    let mut e = Enforcer::new(m, a).await?;
    Ok(())
}
```

## Features

- `postgres`
- `mysql`
- `sqlite`

*Attention*: `postgres`, `mysql`, `sqlite` are mutual exclusive which means that you can only activate one of them.
