use crate::diesel::PgExpressionMethods;
use crate::schema;
use crate::Error;
use casbin::Result;
use diesel::{
    self,
    r2d2::{ConnectionManager, PooledConnection},
    result::Error as DieselError,
    sql_query, BoolExpressionMethods, ExpressionMethods, PgConnection, QueryDsl, RunQueryDsl,
};

use std::error::Error as StdError;

use crate::adapter::TABLE_NAME;

pub type Connection = PgConnection;
type Pool = PooledConnection<ConnectionManager<Connection>>;

pub fn new(conn: Result<Pool>) -> Result<usize> {
    conn.and_then(|conn| {
        sql_query(format!(
            r#"
                CREATE TABLE IF NOT EXISTS {} (
                    id SERIAL PRIMARY KEY,
                    ptype VARCHAR,
                    v0 VARCHAR,
                    v1 VARCHAR,
                    v2 VARCHAR,
                    v3 VARCHAR,
                    v4 VARCHAR,
                    v5 VARCHAR,
                    CONSTRAINT unique_key UNIQUE(ptype, v0, v1, v2, v3, v4, v5)
                );
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
                v0.is_not_distinct_from(rule.get(0)).and(
                    v1.is_not_distinct_from(rule.get(1))
                        .and(v2.is_not_distinct_from(rule.get(2)))
                        .and(
                            v3.is_not_distinct_from(rule.get(3))
                                .and(v4.is_not_distinct_from(rule.get(4)))
                                .and(v5.is_not_distinct_from(rule.get(5))),
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

pub fn remove_filtered_policy(
    conn: Pool,
    pt: &str,
    field_index: usize,
    field_values: Vec<&str>,
) -> Result<bool> {
    use schema::casbin_rules::dsl::*;

    (if field_index == 0 {
        diesel::delete(
            casbin_rules.filter(
                ptype.eq(pt).and(
                    v0.is_not_distinct_from(field_values.get(0)).and(
                        v1.is_not_distinct_from(field_values.get(1))
                            .and(v2.is_not_distinct_from(field_values.get(2)))
                            .and(
                                v3.is_not_distinct_from(field_values.get(3))
                                    .and(v4.is_not_distinct_from(field_values.get(4)))
                                    .and(v5.is_not_distinct_from(field_values.get(5))),
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
                    v1.is_not_distinct_from(field_values.get(0))
                        .and(v2.is_not_distinct_from(field_values.get(1)))
                        .and(
                            v3.is_not_distinct_from(field_values.get(2))
                                .and(v4.is_not_distinct_from(field_values.get(3)))
                                .and(v5.is_not_distinct_from(field_values.get(4))),
                        ),
                ),
            ),
        )
        .execute(&conn)
    } else if field_index == 2 {
        diesel::delete(
            casbin_rules.filter(
                ptype.eq(pt).and(
                    v2.is_not_distinct_from(field_values.get(0))
                        .and(v3.is_not_distinct_from(field_values.get(1)))
                        .and(v4.is_not_distinct_from(field_values.get(2))),
                ),
            ),
        )
        .execute(&conn)
    } else if field_index == 3 {
        diesel::delete(
            casbin_rules.filter(
                ptype.eq(pt).and(
                    v3.is_not_distinct_from(field_values.get(0))
                        .and(v4.is_not_distinct_from(field_values.get(1)))
                        .and(v5.is_not_distinct_from(field_values.get(2))),
                ),
            ),
        )
        .execute(&conn)
    } else if field_index == 4 {
        diesel::delete(
            casbin_rules.filter(
                ptype
                    .eq(pt)
                    .and(v4.is_not_distinct_from(field_values.get(0)))
                    .and(v5.is_not_distinct_from(field_values.get(1))),
            ),
        )
        .execute(&conn)
    } else {
        diesel::delete(
            casbin_rules.filter(
                ptype
                    .eq(pt)
                    .and(v5.is_not_distinct_from(field_values.get(0))),
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
