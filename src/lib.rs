#![feature(stmt_expr_attributes)]
#[macro_use]
extern crate diesel;
#[macro_use]
extern crate cfg_if;

mod adapter;
mod models;
mod schema;

pub use adapter::DieselAdapter;
pub use models::ConnOptions;
