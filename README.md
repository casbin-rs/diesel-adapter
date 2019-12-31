# diesel-adapter

An adapter designed to work with [casbin-rs](https://github.com/casbin/casbin-rs).


## Install

Add it to `Cargo.toml`

```
diesel_adapter = { version = "0.1.0", features = ["postgres"] }
```


## Example

```rust
extern crate casbin;
extern crate diesel_adapter;

use casbin::{Enforcer, FileAdapter, Model};
use diesel_adapter::{DieselAdapter, ConnOptions};

let mut m = Model::new();
m.load_model("examples/rbac_model.conf");

let mut conn_opts = ConnOptions::default();
conn_opts.set_auth("casbin_rs", "casbin_rs");

let adapter = DieselAdapter::new(conn_opts);
let mut e = Enforcer::new(m, adapter);
```

## Features

- `postgres`
- `mysql`

*Attention*: `postgres` and `mysql` are mutual exclusive which means that you can only activate one of them. Currently we don't have support for `sqlite`, it may be added in the near future.
