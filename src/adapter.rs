use async_trait::async_trait;
use casbin::{Adapter, Model, Result};
use diesel::{
    self,
    r2d2::{ConnectionManager, Pool},
    result::Error as DieselError,
    Connection, RunQueryDsl,
};

use crate::{error::*, models::*, schema};

use std::error::Error as StdError;

#[cfg(feature = "mysql")]
use crate::databases::mysql as adapter;
#[cfg(feature = "postgres")]
use crate::databases::postgresql as adapter;

pub struct DieselAdapter {
    pool: Pool<ConnectionManager<adapter::Connection>>,
}

pub const TABLE_NAME: &str = "casbin_rules";

impl<'a> DieselAdapter {
    pub fn new(conn_opts: ConnOptions) -> Result<Self> {
        let manager = ConnectionManager::new(conn_opts.get_url());
        let pool = Pool::builder().build(manager).map_err(Error::PoolError)?;

        let conn = pool
            .get()
            .map_err(|err| Box::new(Error::PoolError(err)) as Box<dyn StdError>);

        adapter::new(conn).map(|_| Self { pool })
    }

    pub(crate) fn save_policy_line(
        &self,
        ptype: &'a str,
        rule: Vec<&'a str>,
    ) -> Option<NewCasbinRule<'a>> {
        if ptype.trim().is_empty() || rule.is_empty() {
            return None;
        }

        let mut new_rule = NewCasbinRule {
            ptype,
            v0: "",
            v1: "",
            v2: "",
            v3: "",
            v4: "",
            v5: "",
        };

        new_rule.v0 = rule[0];

        if rule.len() > 1 {
            new_rule.v1 = rule[1];
        }

        if rule.len() > 2 {
            new_rule.v2 = rule[2];
        }

        if rule.len() > 3 {
            new_rule.v3 = rule[3];
        }

        if rule.len() > 4 {
            new_rule.v4 = rule[4];
        }

        if rule.len() > 5 {
            new_rule.v5 = rule[5];
        }

        Some(new_rule)
    }

    pub(crate) fn load_policy_line(&self, casbin_rule: &CasbinRule) -> Option<Vec<String>> {
        if casbin_rule.ptype.chars().next().is_some() {
            return self.normalize_policy(casbin_rule);
        }

        None
    }

    fn normalize_policy(&self, casbin_rule: &CasbinRule) -> Option<Vec<String>> {
        let mut result = vec![
            &casbin_rule.v0,
            &casbin_rule.v1,
            &casbin_rule.v2,
            &casbin_rule.v3,
            &casbin_rule.v4,
            &casbin_rule.v5,
        ];

        while let Some(last) = result.last() {
            if last.is_empty() {
                result.pop();
            } else {
                break;
            }
        }

        if !result.is_empty() {
            return Some(result.iter().map(|&x| x.to_owned()).collect());
        }

        None
    }
}

#[async_trait]
impl Adapter for DieselAdapter {
    async fn load_policy(&self, m: &mut dyn Model) -> Result<()> {
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

            if let Some(ref sec) = casbin_rule.ptype.chars().next().map(|x| x.to_string()) {
                if let Some(t1) = m.get_mut_model().get_mut(sec) {
                    if let Some(t2) = t1.get_mut(&casbin_rule.ptype) {
                        if let Some(rule) = rule {
                            t2.get_mut_policy().insert(rule);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    async fn save_policy(&mut self, m: &mut dyn Model) -> Result<()> {
        use schema::casbin_rules::dsl::casbin_rules;

        let conn = self
            .pool
            .get()
            .map_err(|err| Box::new(Error::PoolError(err)) as Box<dyn StdError>)?;

        diesel::delete(casbin_rules)
            .execute(&conn)
            .map_err(|err| Box::new(Error::DieselError(err)) as Box<dyn StdError>)?;

        let mut rules = vec![];

        if let Some(ast_map) = m.get_model().get("p") {
            for (ptype, ast) in ast_map {
                let new_rules = ast.get_policy().into_iter().filter_map(|x: &Vec<String>| {
                    self.save_policy_line(
                        ptype,
                        x.iter().map(|y| y.as_str()).collect::<Vec<&str>>(),
                    )
                });

                rules.extend(new_rules);
            }
        }

        if let Some(ast_map) = m.get_model().get("g") {
            for (ptype, ast) in ast_map {
                let new_rules = ast.get_policy().into_iter().filter_map(|x: &Vec<String>| {
                    self.save_policy_line(
                        ptype,
                        x.iter().map(|y| y.as_str()).collect::<Vec<&str>>(),
                    )
                });

                rules.extend(new_rules);
            }
        }

        conn.transaction::<_, DieselError, _>(|| {
            diesel::insert_into(casbin_rules)
                .values(&rules)
                .execute(&conn)
                .map_err(|_| DieselError::RollbackTransaction)
        })
        .map(|_| ())
        .map_err(|err| Box::new(Error::DieselError(err)) as Box<dyn StdError>)
    }

    async fn add_policy(&mut self, _sec: &str, ptype: &str, rule: Vec<&str>) -> Result<bool> {
        use schema::casbin_rules::dsl::casbin_rules;

        let conn = self
            .pool
            .get()
            .map_err(|err| Box::new(Error::PoolError(err)) as Box<dyn StdError>)?;

        if let Some(new_rule) = self.save_policy_line(ptype, rule) {
            return diesel::insert_into(casbin_rules)
                .values(&new_rule)
                .execute(&conn)
                .map(|n| if n == 1 { true } else { false })
                .map_err(|err| Box::new(Error::DieselError(err)) as Box<dyn StdError>);
        }

        Ok(false)
    }

    async fn add_policies(
        &mut self,
        _sec: &str,
        ptype: &str,
        rules: Vec<Vec<&str>>,
    ) -> Result<bool> {
        use schema::casbin_rules::dsl::casbin_rules;

        let conn = self
            .pool
            .get()
            .map_err(|err| Box::new(Error::PoolError(err)) as Box<dyn StdError>)?;

        let new_rules = rules
            .into_iter()
            .filter_map(|x: Vec<&str>| self.save_policy_line(ptype, x))
            .collect::<Vec<NewCasbinRule>>();

        conn.transaction::<_, DieselError, _>(|| {
            diesel::insert_into(casbin_rules)
                .values(&new_rules)
                .execute(&conn)
                .map_err(|_| DieselError::RollbackTransaction)
        })
        .map(|_| true)
        .map_err(|err| Box::new(Error::DieselError(err)) as Box<dyn StdError>)
    }

    async fn remove_policy(&mut self, _sec: &str, pt: &str, rule: Vec<&str>) -> Result<bool> {
        let conn = self
            .pool
            .get()
            .map_err(|err| Box::new(Error::PoolError(err)) as Box<dyn StdError>)?;

        adapter::remove_policy(conn, pt, rule)
    }

    async fn remove_policies(
        &mut self,
        _sec: &str,
        pt: &str,
        rules: Vec<Vec<&str>>,
    ) -> Result<bool> {
        let conn = self
            .pool
            .get()
            .map_err(|err| Box::new(Error::PoolError(err)) as Box<dyn StdError>)?;

        adapter::remove_policies(conn, pt, rules)
    }

    async fn remove_filtered_policy(
        &mut self,
        _sec: &str,
        pt: &str,
        field_index: usize,
        field_values: Vec<&str>,
    ) -> Result<bool> {
        if field_index <= 5 && !field_values.is_empty() && field_values.len() >= 6 - field_index {
            let conn = self
                .pool
                .get()
                .map_err(|err| Box::new(Error::PoolError(err)) as Box<dyn StdError>)?;

            adapter::remove_filtered_policy(conn, pt, field_index, field_values)
        } else {
            Ok(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg_attr(feature = "runtime-async-std", async_std::test)]
    #[cfg_attr(feature = "runtime-tokio", tokio::test)]
    async fn test_adapter() {
        use casbin::{DefaultModel, Enforcer, FileAdapter};

        let mut conn_opts = ConnOptions::default();
        conn_opts.set_auth("casbin_rs", "casbin_rs");
        let file_adapter = Box::new(FileAdapter::new("examples/rbac_policy.csv"));

        let m = DefaultModel::from_file("examples/rbac_model.conf")
            .await
            .unwrap();

        let mut e = Enforcer::new(Box::new(m), file_adapter).await.unwrap();
        let mut adapter = DieselAdapter::new(conn_opts).unwrap();

        assert!(adapter.save_policy(e.get_mut_model()).await.is_ok());

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
            .remove_policies(
                "",
                "p",
                vec![
                    vec!["alice", "data1", "read"],
                    vec!["bob", "data2", "write"],
                    vec!["data2_admin", "data2", "read"],
                    vec!["data2_admin", "data2", "write"],
                ]
            )
            .await
            .is_ok());

        assert!(adapter
            .add_policies(
                "",
                "p",
                vec![
                    vec!["alice", "data1", "read"],
                    vec!["bob", "data2", "write"],
                    vec!["data2_admin", "data2", "read"],
                    vec!["data2_admin", "data2", "write"],
                ]
            )
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
        assert!(adapter
            .add_policy("", "g", vec!["alice", "data2_admin"])
            .await
            .is_err());

        assert!(!adapter
            .remove_filtered_policy("", "g", 0, vec!["alice", "data2_admin", "not_exists"],)
            .await
            .unwrap());

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
    }
}
