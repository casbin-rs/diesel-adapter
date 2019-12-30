use casbin::{Adapter, Model, Result};
use diesel::{
    self,
    pg::PgConnection,
    r2d2::{ConnectionManager, Pool},
    result::Error as DieselError,
    sql_query, BoolExpressionMethods, ExpressionMethods, PgExpressionMethods, QueryDsl,
    RunQueryDsl,
};

use crate::{error::*, models::*, schema};

#[cfg(feature = "postgres")]
pub struct DieselAdapter {
    pool: Pool<ConnectionManager<PgConnection>>,
}

impl<'a> DieselAdapter {
    pub fn new(conn_opts: ConnOptions) -> Result<Self> {
        let manager = ConnectionManager::new(conn_opts.get_url());
        let pool = Pool::builder().build(manager).map_err(Error::PoolError)?;

        pool.get()
            .map_err(|err| Box::new(Error::PoolError(err)))
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
                                v5 VARCHAR
                            );
                        "#,
                    conn_opts.get_table()
                ))
                .execute(&conn)
                .map_err(|err| Box::new(Error::DieselError(err)))
            })
            .map(|_x| Self { pool })
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

impl Adapter for DieselAdapter {
    fn load_policy(&self, m: &mut Model) -> Result<()> {
        use schema::casbin_rules::dsl::casbin_rules;

        self.pool
            .get()
            .map_err(|err| Box::new(Error::PoolError(err)))
            .and_then(|conn| {
                casbin_rules
                    .load::<CasbinRule>(&conn)
                    .map_err(|err| Box::new(Error::DieselError(err)))
            })
            .and_then(move |rules: Vec<CasbinRule>| {
                for casbin_rule in &rules {
                    let rule = self.load_policy_line(casbin_rule);

                    if let Some(ref ptype) = casbin_rule.ptype {
                        let sec = ptype;
                        if let Some(t1) = m.model.get_mut(sec) {
                            if let Some(t2) = t1.get_mut(ptype) {
                                if let Some(rule) = rule {
                                    t2.policy.push(rule);
                                }
                            }
                        }
                    }
                }

                Ok(())
            })
            .map(|_| ())
    }

    fn save_policy(&self, m: &mut Model) -> Result<()> {
        use schema::casbin_rules::dsl::casbin_rules;

        self.pool
            .get()
            .map_err(|err| Box::new(Error::PoolError(err)))
            .and_then(|conn| {
                diesel::delete(casbin_rules)
                    .execute(&conn)
                    .map(move |_| conn)
                    .map_err(|err| Box::new(Error::DieselError(err)))
            })
            .and_then(|conn| {
                // Todo: correctly return errors
                if let Some(ast_map) = m.model.get("p") {
                    for (ptype, ast) in ast_map {
                        ast.policy.iter().for_each(|rule| {
                            let new_rule = self.save_policy_line(
                                ptype,
                                rule.iter().map(|x| x.as_str()).collect::<Vec<&str>>(),
                            );

                            diesel::insert_into(casbin_rules)
                                .values(&new_rule)
                                .execute(&conn)
                                .map_err(|err| Box::new(Error::DieselError(err)));
                        });
                    }
                }

                if let Some(ast_map) = m.model.get("g") {
                    for (ptype, ast) in ast_map {
                        ast.policy.iter().for_each(|rule| {
                            let new_rule = self.save_policy_line(
                                ptype,
                                rule.iter().map(|x| x.as_str()).collect::<Vec<&str>>(),
                            );

                            diesel::insert_into(casbin_rules)
                                .values(&new_rule)
                                .execute(&conn)
                                .map_err(|err| Box::new(Error::DieselError(err)));
                        });
                    }
                }

                Ok(())
            })
            .map(|_| ())
    }

    fn add_policy(&mut self, _sec: &str, ptype: &str, rule: Vec<&str>) -> Result<bool> {
        use schema::casbin_rules::dsl::casbin_rules;

        self.pool
            .get()
            .map_err(|err| Box::new(Error::PoolError(err)))
            .and_then(move |conn| {
                let new_rule = self.save_policy_line(ptype, rule);

                diesel::insert_into(casbin_rules)
                    .values(&new_rule)
                    .execute(&conn)
                    .map_err(|err| Box::new(Error::DieselError(err)))
            })
            .map(|_| true)
    }

    fn remove_policy(&self, _sec: &str, pt: &str, rule: Vec<&str>) -> Result<bool> {
        use schema::casbin_rules::dsl::*;

        self.pool
            .get()
            .map_err(|err| Box::new(Error::PoolError(err)))
            .and_then(move |conn| {
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
                        Ok(())
                    } else {
                        Err(DieselError::NotFound)
                    }
                })
                .map_err(|err| Box::new(Error::DieselError(err)))
            })
            .map(|_| true)
    }

    fn remove_filtered_policy(
        &self,
        _sec: &str,
        pt: &str,
        field_index: usize,
        field_values: Vec<&str>,
    ) -> Result<bool> {
        use schema::casbin_rules::dsl::*;

        if field_index <= 5 && !field_values.is_empty() && field_values.len() <= 6 - field_index {
            self.pool
                .get()
                .map_err(|err| Box::new(Error::PoolError(err)))
                .and_then(|conn| {
                    if field_index == 0 {
                        diesel::delete(
                            casbin_rules.filter(
                                ptype.eq(pt).and(
                                    v0.is_not_distinct_from(field_values.get(0)).and(
                                        v1.is_not_distinct_from(field_values.get(1))
                                            .and(v2.is_not_distinct_from(field_values.get(2)))
                                            .and(
                                                v3.is_not_distinct_from(field_values.get(3))
                                                    .and(
                                                        v4.is_not_distinct_from(
                                                            field_values.get(4),
                                                        ),
                                                    )
                                                    .and(
                                                        v5.is_not_distinct_from(
                                                            field_values.get(5),
                                                        ),
                                                    ),
                                            ),
                                    ),
                                ),
                            ),
                        )
                        .execute(&conn)
                        .map_err(|err| Box::new(Error::DieselError(err)))
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
                        .map_err(|err| Box::new(Error::DieselError(err)))
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
                        .map_err(|err| Box::new(Error::DieselError(err)))
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
                        .map_err(|err| Box::new(Error::DieselError(err)))
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
                        .map_err(|err| Box::new(Error::DieselError(err)))
                    } else {
                        diesel::delete(
                            casbin_rules.filter(
                                ptype
                                    .eq(pt)
                                    .and(v5.is_not_distinct_from(field_values.get(0))),
                            ),
                        )
                        .execute(&conn)
                        .map_err(|err| Box::new(Error::DieselError(err)))
                    }
                })
                .and_then(|n| {
                    if n == 1 {
                        Ok(())
                    } else {
                        Err(Box::new(Error::DieselError(DieselError::NotFound)))
                    }
                })
                .map(|_| true)
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
        use crate::adapter::FileAdapter;
        use crate::enforcer::Enforcer;
        use crate::model::Model;

        let mut m = Model::new();
        m.load_model("examples/rbac_model.conf");

        let mut conn_opts = ConnOptions::default();
        conn_opts.set_auth("casbin_rs", "casbin_rs");
        let file_adapter = FileAdapter::new("examples/rbac_policy.csv");

        let mut e = Enforcer::new(m, file_adapter);
        let adapter = DieselAdapter::new(conn_opts);
        assert!(adapter.is_ok());

        if let Ok(mut adapter) = adapter {
            adapter.save_policy(&mut e.model);

            assert!(adapter.remove_policy("", "p", vec!["alice", "data1", "read"]));
            assert!(adapter.remove_policy("", "p", vec!["bob", "data2", "write"]));
            assert!(adapter.remove_policy("", "p", vec!["data2_admin", "data2", "read"]));
            assert!(adapter.remove_policy("", "p", vec!["data2_admin", "data2", "write"]));
            assert!(adapter.remove_policy("", "g", vec!["alice", "data2_admin"]));

            assert!(adapter.add_policy("", "p", vec!["alice", "data1", "read"]));
            assert!(adapter.add_policy("", "p", vec!["bob", "data2", "write"]));
            assert!(adapter.add_policy("", "p", vec!["data2_admin", "data2", "read"]));
            assert!(adapter.add_policy("", "p", vec!["data2_admin", "data2", "write"]));
            assert!(adapter.add_policy("", "g", vec!["alice", "data2_admin"]));

            assert!(adapter.remove_policy("", "p", vec!["alice", "data1", "read"]));
            assert!(adapter.remove_policy("", "p", vec!["bob", "data2", "write"]));
            assert!(adapter.remove_policy("", "p", vec!["data2_admin", "data2", "read"]));
            assert!(adapter.remove_policy("", "p", vec!["data2_admin", "data2", "write"]));
            assert!(adapter.remove_policy("", "g", vec!["alice", "data2_admin"]));

            assert!(!adapter.remove_policy("", "g", vec!["alice", "data2_admin", "not_exists"]));

            assert!(adapter.add_policy("", "g", vec!["alice", "data2_admin"]));
            assert!(!adapter.remove_filtered_policy(
                "",
                "g",
                0,
                vec!["alice", "data2_admin", "not_exists"],
            ));
            assert!(adapter.remove_filtered_policy("", "g", 0, vec!["alice", "data2_admin"]));

            assert!(adapter.add_policy(
                "",
                "g",
                vec!["alice", "data2_admin", "domain1", "domain2"],
            ));
            assert!(adapter.remove_filtered_policy(
                "",
                "g",
                1,
                vec!["data2_admin", "domain1", "domain2"],
            ));
        }
    }
}
