use casbin::Result;
use crate::Error;
use diesel::{
    self,
    result::Error as DieselError,
    sql_query, BoolExpressionMethods, ExpressionMethods, QueryDsl, RunQueryDsl,
    r2d2::{ConnectionManager, PooledConnection},
    MysqlConnection, dsl::sql,
};
use crate::schema;

use std::error::Error as StdError;

use crate::adapter::TABLE_NAME;

macro_rules! eq_null {
    ($v:expr,$field:expr) => {{
        || {
            use crate::diesel::BoolExpressionMethods;

            sql("")
                .bind::<diesel::sql_types::Bool, _>($v.is_none())
                .and($field.is_null())
                .or(sql("")
                    .bind::<diesel::sql_types::Bool, _>(!$v.is_none())
                    .and($field.eq($v)))
        }
    }
    ()};
}

pub type Connection = MysqlConnection;
type Pool = PooledConnection<ConnectionManager<Connection>>;

pub fn new(conn: Result<Pool>) -> Result<usize>{
    conn
        .and_then(|conn| {
            sql_query(format!(
                r#"
                    CREATE TABLE IF NOT EXISTS {} (
                        id INT NOT NULL AUTO_INCREMENT,
                        ptype VARCHAR(12),
                        v0 VARCHAR(128),
                        v1 VARCHAR(128),
                        v2 VARCHAR(128),
                        v3 VARCHAR(128),
                        v4 VARCHAR(128),
                        v5 VARCHAR(128),
                        PRIMARY KEY(id),
                        CONSTRAINT unique_key UNIQUE(ptype, v0, v1, v2, v3, v4, v5)
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8;
                "#,
                TABLE_NAME
            ))
                .execute(&conn)
                .map_err(|err| Box::new(Error::DieselError(err)) as Box<dyn StdError>)
        })
}

pub fn remove_policy(conn: Pool, pt: &str, rule: Vec<&str>) -> Result<bool> {
    use schema::casbin_rules::dsl::*;

    diesel::delete(
        casbin_rules.filter(
            ptype.eq(pt).and(
                eq_null!(rule.get(0), v0).and(
                    eq_null!(rule.get(1), v1)
                        .and(eq_null!(rule.get(2), v2))
                        .and(
                            eq_null!(rule.get(3), v3)
                                .and(eq_null!(rule.get(4), v4))
                                .and(eq_null!(rule.get(5), v5)),
                        ),
                ),
            ),
        ),
    )
        .execute(&conn)
        .and_then(|n| {
            if n == 1 {
                Ok(true)
            } else {
                Err(DieselError::NotFound)
            }
        })
        .map_err(|err| Box::new(Error::DieselError(err)) as Box<dyn StdError>)
}

pub fn remove_filtered_policy(conn: Pool, pt: &str, field_index: usize, field_values: Vec<&str>) -> Result<bool> {
    use schema::casbin_rules::dsl::*;

    (if field_index == 0 {

        diesel::delete(
            casbin_rules.filter(
                ptype.eq(pt).and(
                    eq_null!(field_values.get(0), v0).and(
                        eq_null!(field_values.get(1), v1)
                            .and(eq_null!(field_values.get(2), v2))
                            .and(
                                eq_null!(field_values.get(3), v3)
                                    .and(eq_null!(field_values.get(4), v4))
                                    .and(eq_null!(field_values.get(5), v5)),
                            ),
                    ),
                ),
            ),
        )
            .execute(&conn)
    } else if field_index == 1 {
        diesel::delete(
            casbin_rules.filter(
                ptype.eq(pt).and(
                    eq_null!(field_values.get(0), v1)
                        .and(eq_null!(field_values.get(1), v2))
                        .and(
                            eq_null!(field_values.get(2), v3)
                                .and(eq_null!(field_values.get(3), v4))
                                .and(eq_null!(field_values.get(4), v5)),
                        ),
                ),
            ),
        )
            .execute(&conn)
    } else if field_index == 2 {
        diesel::delete(
            casbin_rules.filter(
                ptype.eq(pt).and(
                    eq_null!(field_values.get(0), v2)
                        .and(eq_null!(field_values.get(1), v3))
                        .and(eq_null!(field_values.get(2), v4)),
                ),
            ),
        )
            .execute(&conn)
    } else if field_index == 3 {
        diesel::delete(
            casbin_rules.filter(
                ptype.eq(pt).and(
                    eq_null!(field_values.get(0), v3)
                        .and(eq_null!(field_values.get(1), v4))
                        .and(eq_null!(field_values.get(2), v5)),
                ),
            ),
        )
            .execute(&conn)
    } else if field_index == 4 {
        diesel::delete(
            casbin_rules.filter(
                ptype
                    .eq(pt)
                    .and(eq_null!(field_values.get(0), v4))
                    .and(eq_null!(field_values.get(1), v5)),
            ),
        )
            .execute(&conn)
    } else {
        diesel::delete(
            casbin_rules.filter(
                ptype
                    .eq(pt)
                    .and(eq_null!(field_values.get(0), v5)),
            ),
        )
            .execute(&conn)
    })
        .map_err(|err| Box::new(Error::DieselError(err)) as Box<dyn StdError>)
        .and_then(|n| {
            if n == 1 {
                Ok(true)
            } else {
                Err(Box::new(Error::DieselError(DieselError::NotFound)) as Box<dyn StdError>)
            }
        })
}

