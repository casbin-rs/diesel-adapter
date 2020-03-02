#[macro_use]
extern crate diesel;

mod adapter;
mod error;

#[macro_use]
mod macros;
mod models;
mod schema;

mod databases;

pub use adapter::DieselAdapter;
pub use error::Error;
pub use models::ConnOptions;
