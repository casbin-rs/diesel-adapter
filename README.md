# Diesel Adapter for Casbin-RS (Rust)

[![Crates.io](https://img.shields.io/crates/v/diesel-adapter.svg)](https://crates.io/crates/diesel-adapter)
[![Docs](https://docs.rs/diesel-adapter/badge.svg)](https://docs.rs/diesel-adapter)
[![CI](https://github.com/casbin-rs/diesel-adapter/workflows/CI/badge.svg)](https://github.com/casbin-rs/diesel-adapter/actions)
[![codecov](https://codecov.io/gh/casbin-rs/diesel-adapter/branch/master/graph/badge.svg)](https://codecov.io/gh/casbin-rs/diesel-adapter)

Diesel Adapter is the [Diesel](https://github.com/diesel-rs/diesel) adapter for [Casbin-rs](https://github.com/casbin/casbin-rs). With this library, Casbin can load policy from Diesel supported database or save policy to it.

Based on [Diesel](https://github.com/diesel-rs/diesel), The current supported databases are:

- [MySQL](https://www.mysql.com/)
- [PostgreSQL](https://github.com/lib/pq)
- [SQLite](https://www.sqlite.org)

*Attention*: `postgres`, `mysql`, `sqlite` are mutual exclusive which means that you can only activate one of them.

## Notice

In order to unify the database table name in Casbin ecosystem, we decide to use `casbin_rule` instead of `casbin_rules` from version `0.9.0`. If you are using old version `diesel-adapter` in your production environment, please use following command and update `diesel-adapter` version:

````SQL
# MySQL & PostgreSQL & SQLite
ALTER TABLE casbin_rules RENAME TO casbin_rule;
````

## Install

Add it to `Cargo.toml`

```
diesel-adapter = { version = "0.9.0", features = ["postgres"] }
tokio = { version = "1.1.1", features = ["macros", "rt-multi-thread"] }
```
**Warning**: `tokio v1.0` or later is supported from `diesel-adapter v0.9.0`, we recommend that you upgrade the relevant components to ensure that they work properly. The last version that supports `tokio v0.2` is `diesel-adapter v0.8.3` , you can choose according to your needs.

## Configure

Configure `env`

Rename `sample.env` to `.env` and put `DATABASE_URL`, `POOL_SIZE`   inside

```bash
DATABASE_URL=postgres://casbin_rs:casbin_rs@localhost:5432/casbin
# DATABASE_URL=mysql://casbin_rs:casbin_rs@localhost:3306/casbin
# DATABASE_URL=casbin.db
POOL_SIZE=8
```

Or you can export `DATABASE_URL`, `POOL_SIZE`

```bash
export DATABASE_URL=postgres://casbin_rs:casbin_rs@localhost:5432/casbin
export POOL_SIZE=8
```

## Example

```rust
use diesel_adapter::casbin::prelude::*;
use diesel_adapter::DieselAdapter;

#[tokio::main]
async fn main() -> Result<()> {
    let mut m = DefaultModel::from_file("examples/rbac_model.conf").await?;
    let a = DieselAdapter::new("postgres://casbin_rs:casbin_rs@127.0.0.1:5432/casbin", 8)?;
    let mut e = Enforcer::new(m, a).await?;
    Ok(())
}
```
