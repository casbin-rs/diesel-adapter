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

type Pool = PooledConnection<ConnectionManager<Connection>>;

#[cfg(feature = "postgres")]
pub fn new(conn: Result<Pool>) -> Result<usize> {
    conn.and_then(|conn| {
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
                    CONSTRAINT unique_key UNIQUE(ptype, v0, v1, v2, v3, v4, v5)
                );
            "#,
            TABLE_NAME
        ))
        .execute(&conn)
        .map_err(|err| AdapterError(Box::new(Error::DieselError(err))).into())
    })
}

#[cfg(feature = "mysql")]
pub fn new(conn: Result<Pool>) -> Result<usize> {
    conn.and_then(|conn| {
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
                    CONSTRAINT unique_key UNIQUE(ptype, v0, v1, v2, v3, v4, v5)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8;
            "#,
            TABLE_NAME
        ))
        .execute(&conn)
        .map_err(|err| AdapterError(Box::new(Error::DieselError(err))).into())
    })
}

pub fn remove_policy(conn: Pool, pt: &str, rule: Vec<String>) -> Result<bool> {
    use schema::casbin_rules::dsl::*;

    let rule = normalize_casbin_rule(rule, 0);

    let filter = ptype
        .eq(pt)
        .and(v0.eq(&rule[0]))
        .and(v1.eq(&rule[1]))
        .and(v2.eq(&rule[2]))
        .and(v3.eq(&rule[3]))
        .and(v4.eq(&rule[4]))
        .and(v5.eq(&rule[5]));

    diesel::delete(casbin_rules.filter(filter))
        .execute(&conn)
        .and_then(|n| {
            if n == 1 {
                Ok(true)
            } else {
                Err(DieselError::NotFound)
            }
        })
        .map_err(|err| AdapterError(Box::new(Error::DieselError(err))).into())
}

pub fn remove_policies(conn: Pool, pt: &str, rules: Vec<Vec<String>>) -> Result<bool> {
    use schema::casbin_rules::dsl::*;

    conn.transaction::<_, DieselError, _>(|| {
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

            match diesel::delete(casbin_rules.filter(filter)).execute(&conn) {
                Ok(n) if n == 1 => continue,
                _ => return Err(DieselError::RollbackTransaction),
            }
        }

        Ok(true)
    })
    .map_err(|err| AdapterError(Box::new(Error::DieselError(err))).into())
}

pub fn remove_filtered_policy(
    conn: Pool,
    pt: &str,
    field_index: usize,
    field_values: Vec<String>,
) -> Result<bool> {
    use schema::casbin_rules::dsl::*;

    let field_values = normalize_casbin_rule(field_values, field_index);

    let boxed_query = if field_index == 5 {
        diesel::delete(casbin_rules.filter(ptype.eq(pt).and(eq_empty!(&field_values[0], v5))))
            .into_boxed()
    } else if field_index == 4 {
        diesel::delete(
            casbin_rules.filter(
                ptype
                    .eq(pt)
                    .and(eq_empty!(&field_values[0], v4))
                    .and(eq_empty!(&field_values[1], v5)),
            ),
        )
        .into_boxed()
    } else if field_index == 3 {
        diesel::delete(
            casbin_rules.filter(
                ptype
                    .eq(pt)
                    .and(eq_empty!(&field_values[0], v3))
                    .and(eq_empty!(&field_values[1], v4))
                    .and(eq_empty!(&field_values[2], v5)),
            ),
        )
        .into_boxed()
    } else if field_index == 2 {
        diesel::delete(
            casbin_rules.filter(
                ptype
                    .eq(pt)
                    .and(eq_empty!(&field_values[0], v2))
                    .and(eq_empty!(&field_values[1], v3))
                    .and(eq_empty!(&field_values[2], v4))
                    .and(eq_empty!(&field_values[3], v5)),
            ),
        )
        .into_boxed()
    } else if field_index == 1 {
        diesel::delete(
            casbin_rules.filter(
                ptype
                    .eq(pt)
                    .and(eq_empty!(&field_values[0], v1))
                    .and(eq_empty!(&field_values[1], v2))
                    .and(eq_empty!(&field_values[2], v3))
                    .and(eq_empty!(&field_values[3], v4))
                    .and(eq_empty!(&field_values[4], v5)),
            ),
        )
        .into_boxed()
    } else {
        diesel::delete(
            casbin_rules.filter(
                ptype
                    .eq(pt)
                    .and(eq_empty!(&field_values[0], v0))
                    .and(eq_empty!(&field_values[1], v1))
                    .and(eq_empty!(&field_values[2], v2))
                    .and(eq_empty!(&field_values[3], v3))
                    .and(eq_empty!(&field_values[4], v4))
                    .and(eq_empty!(&field_values[5], v5)),
            ),
        )
        .into_boxed()
    };

    boxed_query
        .execute(&conn)
        .map_err(|err| AdapterError(Box::new(Error::DieselError(err))).into())
        .and_then(|n| {
            if n == 1 {
                Ok(true)
            } else {
                Err(AdapterError(Box::new(Error::DieselError(DieselError::NotFound))).into())
            }
        })
}

pub(crate) fn save_policy(conn: Pool, rules: Vec<NewCasbinRule>) -> Result<()> {
    use schema::casbin_rules::dsl::casbin_rules;

    conn.transaction::<_, DieselError, _>(|| {
        if diesel::delete(casbin_rules).execute(&conn).is_err() {
            return Err(DieselError::RollbackTransaction);
        }

        diesel::insert_into(casbin_rules)
            .values(&rules)
            .execute(&conn)
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

pub(crate) fn load_policy(conn: Pool) -> Result<Vec<CasbinRule>> {
    use schema::casbin_rules::dsl::casbin_rules;

    casbin_rules
        .load::<CasbinRule>(&conn)
        .map_err(|err| AdapterError(Box::new(Error::DieselError(err))).into())
}

pub(crate) fn add_policy(conn: Pool, new_rule: NewCasbinRule) -> Result<bool> {
    use schema::casbin_rules::dsl::casbin_rules;

    diesel::insert_into(casbin_rules)
        .values(&new_rule)
        .execute(&conn)
        .and_then(|n| if n == 1 { Ok(true) } else { Ok(false) })
        .map_err(|err| AdapterError(Box::new(Error::DieselError(err))).into())
}

pub(crate) fn add_policies(conn: Pool, new_rules: Vec<NewCasbinRule>) -> Result<bool> {
    use schema::casbin_rules::dsl::casbin_rules;

    conn.transaction::<_, DieselError, _>(|| {
        diesel::insert_into(casbin_rules)
            .values(&new_rules)
            .execute(&conn)
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
