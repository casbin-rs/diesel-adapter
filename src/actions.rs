use crate::schema;
use crate::Error;
use casbin::{error::AdapterError, Result};
use diesel::{
    self,
    r2d2::{ConnectionManager, PooledConnection},
    result::Error as DieselError,
    sql_query, BoolExpressionMethods, Connection as DieselConnection, ExpressionMethods, QueryDsl,
    RunQueryDsl,
};

use crate::{
    adapter::TABLE_NAME,
    models::{CasbinRule, NewCasbinRule},
};

#[cfg(feature = "postgres")]
pub type Connection = diesel::PgConnection;
#[cfg(feature = "mysql")]
pub type Connection = diesel::MysqlConnection;
#[cfg(feature = "sqlite")]
pub type Connection = diesel::SqliteConnection;

type Pool = PooledConnection<ConnectionManager<Connection>>;

#[cfg(feature = "postgres")]
pub fn new(conn: Result<Pool>) -> Result<usize> {
    conn.and_then(|mut conn| {
        sql_query(format!(
            r#"
                CREATE TABLE IF NOT EXISTS {} (
                    id SERIAL PRIMARY KEY,
                    ptype VARCHAR NOT NULL,
                    v0 VARCHAR NOT NULL,
                    v1 VARCHAR NOT NULL,
                    v2 VARCHAR NOT NULL,
                    v3 VARCHAR NOT NULL,
                    v4 VARCHAR NOT NULL,
                    v5 VARCHAR NOT NULL,
                    CONSTRAINT unique_key_diesel_adapter UNIQUE(ptype, v0, v1, v2, v3, v4, v5)
                );
            "#,
            TABLE_NAME
        ))
        .execute(&mut conn)
        .map_err(|err| AdapterError(Box::new(Error::DieselError(err))).into())
    })
}

#[cfg(feature = "mysql")]
pub fn new(conn: Result<Pool>) -> Result<usize> {
    conn.and_then(|mut conn| {
        sql_query(format!(
            r#"
                CREATE TABLE IF NOT EXISTS {} (
                    id INT NOT NULL AUTO_INCREMENT,
                    ptype VARCHAR(12) NOT NULL,
                    v0 VARCHAR(128) NOT NULL,
                    v1 VARCHAR(128) NOT NULL,
                    v2 VARCHAR(128) NOT NULL,
                    v3 VARCHAR(128) NOT NULL,
                    v4 VARCHAR(128) NOT NULL,
                    v5 VARCHAR(128) NOT NULL,
                    PRIMARY KEY(id),
                    CONSTRAINT unique_key_diesel_adapter UNIQUE(ptype, v0, v1, v2, v3, v4, v5)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8;
            "#,
            TABLE_NAME
        ))
        .execute(&mut conn)
        .map_err(|err| AdapterError(Box::new(Error::DieselError(err))).into())
    })
}

#[cfg(feature = "sqlite")]
pub fn new(conn: Result<Pool>) -> Result<usize> {
    conn.and_then(|mut conn| {
        sql_query(format!(
            r#"
                CREATE TABLE IF NOT EXISTS {} (
                    id INTEGER PRIMARY KEY,
                    ptype VARCHAR(12) NOT NULL,
                    v0 VARCHAR(128) NOT NULL,
                    v1 VARCHAR(128) NOT NULL,
                    v2 VARCHAR(128) NOT NULL,
                    v3 VARCHAR(128) NOT NULL,
                    v4 VARCHAR(128) NOT NULL,
                    v5 VARCHAR(128) NOT NULL,
                    CONSTRAINT unique_key_diesel_adapter UNIQUE(ptype, v0, v1, v2, v3, v4, v5)
                );
            "#,
            TABLE_NAME
        ))
        .execute(&mut conn)
        .map_err(|err| AdapterError(Box::new(Error::DieselError(err))).into())
    })
}

pub fn remove_policy(mut conn: Pool, pt: &str, rule: Vec<String>) -> Result<bool> {
    use schema::casbin_rule::dsl::*;

    let rule = normalize_casbin_rule(rule, 0);

    let filter = ptype
        .eq(pt)
        .and(v0.eq(&rule[0]))
        .and(v1.eq(&rule[1]))
        .and(v2.eq(&rule[2]))
        .and(v3.eq(&rule[3]))
        .and(v4.eq(&rule[4]))
        .and(v5.eq(&rule[5]));

    diesel::delete(casbin_rule.filter(filter))
        .execute(&mut conn)
        .map(|n| n == 1)
        .map_err(|err| AdapterError(Box::new(Error::DieselError(err))).into())
}

pub fn remove_policies(mut conn: Pool, pt: &str, rules: Vec<Vec<String>>) -> Result<bool> {
    use schema::casbin_rule::dsl::*;

    conn.transaction::<_, DieselError, _>(|conn| {
        for rule in rules {
            let rule = normalize_casbin_rule(rule, 0);

            let filter = ptype
                .eq(pt)
                .and(v0.eq(&rule[0]))
                .and(v1.eq(&rule[1]))
                .and(v2.eq(&rule[2]))
                .and(v3.eq(&rule[3]))
                .and(v4.eq(&rule[4]))
                .and(v5.eq(&rule[5]));

            match diesel::delete(casbin_rule.filter(filter)).execute(conn) {
                Ok(1) => continue,
                _ => return Err(DieselError::RollbackTransaction),
            }
        }

        Ok(true)
    })
    .map_err(|err| AdapterError(Box::new(Error::DieselError(err))).into())
}

pub fn remove_filtered_policy(
    mut conn: Pool,
    pt: &str,
    field_index: usize,
    field_values: Vec<String>,
) -> Result<bool> {
    use schema::casbin_rule::dsl::*;

    let field_values = normalize_casbin_rule(field_values, field_index);

    let boxed_query = if field_index == 5 {
        diesel::delete(casbin_rule)
            .filter(ptype.eq(pt).and(v5.is_null().or(v5.eq(&field_values[0]))))
            .into_boxed()
    } else if field_index == 4 {
        diesel::delete(casbin_rule)
            .filter(
                ptype
                    .eq(pt)
                    .and(v4.is_null().or(v4.eq(&field_values[0])))
                    .and(v5.is_null().or(v5.eq(&field_values[1]))),
            )
            .into_boxed()
    } else if field_index == 3 {
        diesel::delete(casbin_rule)
            .filter(
                ptype
                    .eq(pt)
                    .and(v3.is_null().or(v3.eq(&field_values[0])))
                    .and(v4.is_null().or(v4.eq(&field_values[1])))
                    .and(v5.is_null().or(v5.eq(&field_values[2]))),
            )
            .into_boxed()
    } else if field_index == 2 {
        diesel::delete(casbin_rule)
            .filter(
                ptype
                    .eq(pt)
                    .and(v2.is_null().or(v2.eq(&field_values[0])))
                    .and(v3.is_null().or(v3.eq(&field_values[1])))
                    .and(v4.is_null().or(v4.eq(&field_values[2])))
                    .and(v5.is_null().or(v5.eq(&field_values[3]))),
            )
            .into_boxed()
    } else if field_index == 1 {
        diesel::delete(casbin_rule)
            .filter(
                ptype
                    .eq(pt)
                    .and(v1.is_null().or(v1.eq(&field_values[0])))
                    .and(v2.is_null().or(v2.eq(&field_values[1])))
                    .and(v3.is_null().or(v3.eq(&field_values[2])))
                    .and(v4.is_null().or(v4.eq(&field_values[3])))
                    .and(v5.is_null().or(v5.eq(&field_values[4]))),
            )
            .into_boxed()
    } else {
        diesel::delete(casbin_rule)
            .filter(
                ptype
                    .eq(pt)
                    .and(v0.is_null().or(v0.eq(&field_values[0])))
                    .and(v1.is_null().or(v1.eq(&field_values[1])))
                    .and(v2.is_null().or(v2.eq(&field_values[2])))
                    .and(v3.is_null().or(v3.eq(&field_values[3])))
                    .and(v4.is_null().or(v4.eq(&field_values[4])))
                    .and(v5.is_null().or(v5.eq(&field_values[5]))),
            )
            .into_boxed()
    };

    boxed_query
        .execute(&mut conn)
        .map(|n| n >= 1)
        .map_err(|err| AdapterError(Box::new(Error::DieselError(err))).into())
}

pub(crate) fn clear_policy(mut conn: Pool) -> Result<()> {
    use schema::casbin_rule::dsl::casbin_rule;
    diesel::delete(casbin_rule)
        .execute(&mut conn)
        .map(|_| ())
        .map_err(|err| AdapterError(Box::new(Error::DieselError(err))).into())
}

pub(crate) fn save_policy(mut conn: Pool, rules: Vec<NewCasbinRule>) -> Result<()> {
    use schema::casbin_rule::dsl::casbin_rule;

    conn.transaction::<_, DieselError, _>(|conn| {
        if diesel::delete(casbin_rule).execute(conn).is_err() {
            return Err(DieselError::RollbackTransaction);
        }

        diesel::insert_into(casbin_rule)
            .values(&rules)
            .execute(conn)
            .and_then(|n| {
                if n == rules.len() {
                    Ok(())
                } else {
                    Err(DieselError::RollbackTransaction)
                }
            })
            .map_err(|_| DieselError::RollbackTransaction)
    })
    .map_err(|err| AdapterError(Box::new(Error::DieselError(err))).into())
}

pub(crate) fn load_policy(mut conn: Pool) -> Result<Vec<CasbinRule>> {
    use schema::casbin_rule::dsl::casbin_rule;

    casbin_rule
        .load::<CasbinRule>(&mut conn)
        .map_err(|err| AdapterError(Box::new(Error::DieselError(err))).into())
}

pub(crate) fn add_policy(mut conn: Pool, new_rule: NewCasbinRule) -> Result<bool> {
    use schema::casbin_rule::dsl::casbin_rule;

    diesel::insert_into(casbin_rule)
        .values(&new_rule)
        .execute(&mut conn)
        .map(|n| n == 1)
        .map_err(|err| AdapterError(Box::new(Error::DieselError(err))).into())
}

pub(crate) fn add_policies(mut conn: Pool, new_rules: Vec<NewCasbinRule>) -> Result<bool> {
    use schema::casbin_rule::dsl::casbin_rule;

    conn.transaction::<_, DieselError, _>(|conn| {
        diesel::insert_into(casbin_rule)
            .values(&new_rules)
            .execute(&mut *conn)
            .and_then(|n| {
                if n == new_rules.len() {
                    Ok(true)
                } else {
                    Err(DieselError::RollbackTransaction)
                }
            })
            .map_err(|_| DieselError::RollbackTransaction)
    })
    .map_err(|err| AdapterError(Box::new(Error::DieselError(err))).into())
}

fn normalize_casbin_rule(mut rule: Vec<String>, field_index: usize) -> Vec<String> {
    rule.resize(6 - field_index, String::from(""));
    rule
}
