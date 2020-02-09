use async_trait::async_trait;
use casbin::{Adapter, Model, Result};
use diesel::{
    self,
    r2d2::{ConnectionManager, Pool},
    result::Error as DieselError,
    sql_query, BoolExpressionMethods, ExpressionMethods, QueryDsl, RunQueryDsl,
};

use crate::{error::*, models::*, schema};

use std::error::Error as StdError;

#[cfg(feature = "postgres")]
use diesel::{pg::PgConnection, PgExpressionMethods};

#[cfg(feature = "postgres")]
pub struct DieselAdapter {
    pool: Pool<ConnectionManager<PgConnection>>,
}

#[cfg(feature = "mysql")]
use diesel::{dsl::sql, mysql::MysqlConnection};
#[cfg(feature = "mysql")]
pub struct DieselAdapter {
    pool: Pool<ConnectionManager<MysqlConnection>>,
}
#[cfg(feature = "mysql")]
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

impl<'a> DieselAdapter {
    pub fn new(conn_opts: ConnOptions) -> Result<Self> {
        let manager = ConnectionManager::new(conn_opts.get_url());
        let pool = Pool::builder().build(manager).map_err(Error::PoolError)?;

        cfg_if! {
            if #[cfg(feature = "postgres")] {
                pool.get()
                    .map_err(|err| Box::new(Error::PoolError(err)) as Box<dyn StdError>)
                    .and_then(|conn| {
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
                            conn_opts.get_table()
                        ))
                        .execute(&conn)
                        .map_err(|err| Box::new(Error::DieselError(err)) as Box<dyn StdError>)
                    })
                    .map(|_x| Self { pool })
            } else if #[cfg(feature = "mysql")] {
                pool.get()
                    .map_err(|err| Box::new(Error::PoolError(err)) as Box<dyn StdError>)
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
                            conn_opts.get_table()
                        ))
                        .execute(&conn)
                        .map_err(|err| Box::new(Error::DieselError(err)) as Box<dyn StdError>)
                    })
                    .map(|_x| Self { pool })
            }
        }
    }

    pub(crate) fn save_policy_line(&self, ptype: &'a str, rule: Vec<&'a str>) -> NewCasbinRule<'a> {
        let mut new_rule = NewCasbinRule {
            ptype: Some(ptype),
            v0: None,
            v1: None,
            v2: None,
            v3: None,
            v4: None,
            v5: None,
        };

        if !rule.is_empty() {
            new_rule.v0 = Some(rule[0]);
        }

        if rule.len() > 1 {
            new_rule.v1 = Some(rule[1]);
        }

        if rule.len() > 2 {
            new_rule.v2 = Some(rule[2]);
        }

        if rule.len() > 3 {
            new_rule.v3 = Some(rule[3]);
        }

        if rule.len() > 4 {
            new_rule.v4 = Some(rule[4]);
        }

        if rule.len() > 5 {
            new_rule.v5 = Some(rule[5]);
        }

        new_rule
    }

    pub(crate) fn load_policy_line(&self, casbin_rule: &CasbinRule) -> Option<Vec<String>> {
        if let Some(ref sec) = casbin_rule.ptype {
            if sec.chars().nth(0).is_some() {
                return Some(
                    vec![
                        &casbin_rule.v0,
                        &casbin_rule.v1,
                        &casbin_rule.v2,
                        &casbin_rule.v3,
                        &casbin_rule.v4,
                        &casbin_rule.v5,
                    ]
                    .iter()
                    .filter_map(|&x| x.as_ref().map(|x| x.to_owned()))
                    .collect::<Vec<String>>(),
                );
            }
        }

        None
    }
}

#[async_trait]
impl Adapter for DieselAdapter {
    async fn load_policy(&self, m: &mut Model) -> Result<()> {
        use schema::casbin_rules::dsl::casbin_rules;

        let conn = self
            .pool
            .get()
            .map_err(|err| Box::new(Error::PoolError(err)) as Box<dyn StdError>)?;

        let rules = casbin_rules
            .load::<CasbinRule>(&conn)
            .map_err(|err| Box::new(Error::DieselError(err)) as Box<dyn StdError>)?;

        for casbin_rule in &rules {
            let rule = self.load_policy_line(casbin_rule);

            if let Some(ref ptype) = casbin_rule.ptype {
                if let Some(ref sec) = ptype.chars().next().map(|x| x.to_string()) {
                    if let Some(t1) = m.get_mut_model().get_mut(sec) {
                        if let Some(t2) = t1.get_mut(ptype) {
                            if let Some(rule) = rule {
                                t2.get_mut_policy().insert(rule);
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    async fn save_policy(&self, m: &mut Model) -> Result<()> {
        use schema::casbin_rules::dsl::casbin_rules;

        let conn = self
            .pool
            .get()
            .map_err(|err| Box::new(Error::PoolError(err)) as Box<dyn StdError>)?;

        diesel::delete(casbin_rules)
            .execute(&conn)
            .map_err(|err| Box::new(Error::DieselError(err)) as Box<dyn StdError>)?;

        if let Some(ast_map) = m.get_mut_model().get("p") {
            for (ptype, ast) in ast_map {
                for rule in ast.get_policy() {
                    let new_rule = self.save_policy_line(
                        ptype,
                        rule.iter().map(|x| x.as_str()).collect::<Vec<&str>>(),
                    );

                    if let Err(err) = diesel::insert_into(casbin_rules)
                        .values(&new_rule)
                        .execute(&conn)
                        .map_err(|err| Box::new(Error::DieselError(err)))
                    {
                        return Err(err);
                    }
                }
            }
        }

        if let Some(ast_map) = m.get_mut_model().get("g") {
            for (ptype, ast) in ast_map {
                for rule in ast.get_policy() {
                    let new_rule = self.save_policy_line(
                        ptype,
                        rule.iter().map(|x| x.as_str()).collect::<Vec<&str>>(),
                    );

                    if let Err(err) = diesel::insert_into(casbin_rules)
                        .values(&new_rule)
                        .execute(&conn)
                        .map_err(|err| Box::new(Error::DieselError(err)))
                    {
                        return Err(err);
                    }
                }
            }
        }

        Ok(())
    }

    async fn add_policy(&mut self, _sec: &str, ptype: &str, rule: Vec<&str>) -> Result<bool> {
        use schema::casbin_rules::dsl::casbin_rules;

        let conn = self
            .pool
            .get()
            .map_err(|err| Box::new(Error::PoolError(err)) as Box<dyn StdError>)?;

        let new_rule = self.save_policy_line(ptype, rule);

        diesel::insert_into(casbin_rules)
            .values(&new_rule)
            .execute(&conn)
            .and_then(|n| if n == 1 { Ok(true) } else { Ok(false) })
            .map_err(|err| Box::new(Error::DieselError(err)) as Box<dyn StdError>)
    }

    async fn remove_policy(&self, _sec: &str, pt: &str, rule: Vec<&str>) -> Result<bool> {
        use schema::casbin_rules::dsl::*;

        let conn = self
            .pool
            .get()
            .map_err(|err| Box::new(Error::PoolError(err)) as Box<dyn StdError>)?;

        cfg_if! {
            if #[cfg(feature = "postgres")] {
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
            } else if #[cfg(feature = "mysql")] {
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
        }
    }

    async fn remove_filtered_policy(
        &self,
        _sec: &str,
        pt: &str,
        field_index: usize,
        field_values: Vec<&str>,
    ) -> Result<bool> {
        use schema::casbin_rules::dsl::*;

        if field_index <= 5 && !field_values.is_empty() && field_values.len() <= 6 - field_index {
            let conn = self
                .pool
                .get()
                .map_err(|err| Box::new(Error::PoolError(err)) as Box<dyn StdError>)?;

            cfg_if! {
                if #[cfg(feature = "postgres")] {
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
                } else if #[cfg(feature = "mysql")] {
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
            }
        } else {
            Ok(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adapter() {
        // # Ubuntu
        // sudo apt install libpq-dev libmysqlclient-dev
        //
        // # Deepin
        // sudo apt install libpq-dev libmysql++-dev
        //
        // docker run -itd  --restart always  -e POSTGRES_USER=casbin_rs  -e POSTGRES_PASSWORD=casbin_rs  -e POSTGRES_DB=casbin  -p 5432:5432  -v /srv/docker/postgresql:/var/lib/postgresql  postgres:11;
        // docker run -itd  --restart always -e MYSQL_ALLOW_EMPTY_PASSWORD=yes -e MYSQL_USER=casbin_rs -e MYSQL_PASSWORD=casbin_rs -e MYSQL_DATABASE=casbin -p 3306:3306 -v /srv/docker/mysql:/var/lib/mysql mysql:8 --default-authentication-plugin=mysql_native_password;
        //
        //  # Ubuntu
        //  sudo apt install postgresql-client-11 mysql-client-core-8.0
        //
        //  # Deepin
        //  sudo apt install mysql-client postgresql-client-9.6
        //
        //  psql postgres://casbin_rs:casbin_rs@127.0.0.1:5432/casbin;
        //  mysql -h 127.0.0.1 -u casbin_rs -p
        use async_std::task;
        use casbin::{Enforcer, FileAdapter, Model};

        let mut conn_opts = ConnOptions::default();
        conn_opts.set_auth("casbin_rs", "casbin_rs");
        let file_adapter = Box::new(FileAdapter::new("examples/rbac_policy.csv"));

        task::block_on(async move {
            let m = Model::from_file("examples/rbac_model.conf").await.unwrap();

            let mut e = Enforcer::new(m, file_adapter).await.unwrap();
            let mut adapter = DieselAdapter::new(conn_opts).unwrap();

            assert!(adapter.save_policy(&mut e.get_mut_model()).await.is_ok());

            assert!(adapter
                .remove_policy("", "p", vec!["alice", "data1", "read"])
                .await
                .is_ok());
            assert!(adapter
                .remove_policy("", "p", vec!["bob", "data2", "write"])
                .await
                .is_ok());
            assert!(adapter
                .remove_policy("", "p", vec!["data2_admin", "data2", "read"])
                .await
                .is_ok());
            assert!(adapter
                .remove_policy("", "p", vec!["data2_admin", "data2", "write"])
                .await
                .is_ok());
            assert!(adapter
                .remove_policy("", "g", vec!["alice", "data2_admin"])
                .await
                .is_ok());

            assert!(adapter
                .add_policy("", "p", vec!["alice", "data1", "read"])
                .await
                .is_ok());
            assert!(adapter
                .add_policy("", "p", vec!["bob", "data2", "write"])
                .await
                .is_ok());
            assert!(adapter
                .add_policy("", "p", vec!["data2_admin", "data2", "read"])
                .await
                .is_ok());
            assert!(adapter
                .add_policy("", "p", vec!["data2_admin", "data2", "write"])
                .await
                .is_ok());
            assert!(adapter
                .add_policy("", "g", vec!["alice", "data2_admin"])
                .await
                .is_ok());

            assert!(adapter
                .remove_policy("", "p", vec!["alice", "data1", "read"])
                .await
                .is_ok());
            assert!(adapter
                .remove_policy("", "p", vec!["bob", "data2", "write"])
                .await
                .is_ok());
            assert!(adapter
                .remove_policy("", "p", vec!["data2_admin", "data2", "read"])
                .await
                .is_ok());
            assert!(adapter
                .remove_policy("", "p", vec!["data2_admin", "data2", "write"])
                .await
                .is_ok());
            assert!(adapter
                .remove_policy("", "g", vec!["alice", "data2_admin"])
                .await
                .is_ok());

            assert!(!adapter
                .remove_policy("", "g", vec!["alice", "data2_admin", "not_exists"])
                .await
                .is_ok());

            assert!(adapter
                .add_policy("", "g", vec!["alice", "data2_admin"])
                .await
                .is_ok());
            assert!(!adapter
                .remove_filtered_policy("", "g", 0, vec!["alice", "data2_admin", "not_exists"],)
                .await
                .is_ok());
            assert!(adapter
                .remove_filtered_policy("", "g", 0, vec!["alice", "data2_admin"])
                .await
                .is_ok());

            assert!(adapter
                .add_policy("", "g", vec!["alice", "data2_admin", "domain1", "domain2"],)
                .await
                .is_ok());
            assert!(adapter
                .remove_filtered_policy("", "g", 1, vec!["data2_admin", "domain1", "domain2"],)
                .await
                .is_ok());
        });
    }
}
