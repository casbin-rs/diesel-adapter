use diesel::{r2d2::PoolError, result::Error as DieselError};

use std::{error::Error as StdError, fmt};

#[derive(Debug)]
pub enum Error {
    PoolError(PoolError),
    DieselError(DieselError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Error::*;

        match self {
            PoolError(pool_err) => pool_err.fmt(f),
            DieselError(diesel_error) => diesel_error.fmt(f),
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        use Error::*;

        match self {
            PoolError(pool_err) => Some(pool_err),
            DieselError(diesel_error) => Some(diesel_error),
        }
    }
}
