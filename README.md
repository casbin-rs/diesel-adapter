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
casbin = { version = "0.7.4", default-features = false, features = ["incremental"] }
diesel-adapter = { version = "0.6.1", features = ["postgres"] }
async-std = "1.5.0"
```

## Configure

Rename `sample.env` to `.env` and put `DATABASE_URL`, `POOL_SIZE` inside

```bash
DATABASE_URL=postgres://casbin_rs:casbin_rs@127.0.0.1:5432/casbin
# DATABASE_URL=mysql://casbin_rs:casbin_rs@127.0.0.1:3306/casbin
POOL_SIZE=8
```

Or you can export `DATABASE_URL`, `POOL_SIZE` 

```bash
export DATABASE_URL=postgres://casbin_rs:casbin_rs@127.0.0.1:5432/casbin
export POOL_SIZE=8
```


## Example

```rust
use casbin::prelude::*;
use diesel_adapter::{DieselAdapter, ConnOptions};

#[async_std::main]
async fn main() -> Result<()> {
    let mut m = DefaultModel::from_file("examples/rbac_model.conf").await?;
    let a = DieselAdapter::new()?;
    let mut e = Enforcer::new(m, a).await?;
    Ok(())
}
```

## Features

- `postgres`
- `mysql`

*Attention*: `postgres` and `mysql` are mutual exclusive which means that you can only activate one of them. Currently we don't have support for `sqlite`, it may be added in the near future.
