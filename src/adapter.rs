use async_trait::async_trait;
use casbin::{error::AdapterError, Adapter, Error as CasbinError, Filter, Model, Result};
use diesel::{
    self,
    r2d2::{ConnectionManager, Pool},
};

use crate::{actions as adapter, error::*, models::*};

use std::time::Duration;

pub struct DieselAdapter {
    pool: Pool<ConnectionManager<adapter::Connection>>,
    is_filtered: bool,
}

pub const TABLE_NAME: &str = "casbin_rules";

impl<'a> DieselAdapter {
    pub fn new(conn_opts: ConnOptions) -> Result<Self> {
        let manager = ConnectionManager::new(conn_opts.get_url());
        let pool = Pool::builder()
            .connection_timeout(Duration::from_secs(10))
            .build(manager)
            .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::PoolError(err)))))?;

        let conn = pool
            .get()
            .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::PoolError(err)))));

        adapter::new(conn).map(|_| Self {
            pool,
            is_filtered: false,
        })
    }

    pub(crate) fn save_policy_line(
        &self,
        ptype: &'a str,
        rule: &'a [String],
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

        new_rule.v0 = &rule[0];

        if rule.len() > 1 {
            new_rule.v1 = &rule[1];
        }

        if rule.len() > 2 {
            new_rule.v2 = &rule[2];
        }

        if rule.len() > 3 {
            new_rule.v3 = &rule[3];
        }

        if rule.len() > 4 {
            new_rule.v4 = &rule[4];
        }

        if rule.len() > 5 {
            new_rule.v5 = &rule[5];
        }

        Some(new_rule)
    }

    pub(crate) fn load_policy_line(&self, casbin_rule: &CasbinRule) -> Option<Vec<String>> {
        if casbin_rule.ptype.chars().next().is_some() {
            return self.normalize_policy(casbin_rule);
        }

        None
    }

    pub(crate) fn load_filtered_policy_line(
        &self,
        casbin_rule: &CasbinRule,
        f: &Filter,
    ) -> Option<Vec<String>> {
        if let Some(sec) = casbin_rule.ptype.chars().next() {
            if let Some(policy) = self.normalize_policy(casbin_rule) {
                let mut is_filtered = false;
                if sec == 'p' {
                    for (i, rule) in f.p.iter().enumerate() {
                        if !rule.is_empty() && rule != &policy[i] {
                            is_filtered = true
                        }
                    }
                } else if sec == 'g' {
                    for (i, rule) in f.g.iter().enumerate() {
                        if !rule.is_empty() && rule != &policy[i] {
                            is_filtered = true
                        }
                    }
                } else {
                    return None;
                }

                if !is_filtered {
                    return Some(policy);
                }
            }
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
        let conn = self
            .pool
            .get()
            .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::PoolError(err)))))?;

        let rules = adapter::load_policy(conn)?;

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

    async fn load_filtered_policy(&mut self, m: &mut dyn Model, f: Filter) -> Result<()> {
        let conn = self
            .pool
            .get()
            .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::PoolError(err)))))?;

        let rules = adapter::load_policy(conn)?;

        for casbin_rule in &rules {
            let rule = self.load_filtered_policy_line(casbin_rule, &f);

            if let Some(rule) = rule {
                if let Some(ref sec) = casbin_rule.ptype.chars().next().map(|x| x.to_string()) {
                    if let Some(t1) = m.get_mut_model().get_mut(sec) {
                        if let Some(t2) = t1.get_mut(&casbin_rule.ptype) {
                            t2.get_mut_policy().insert(rule);
                        }
                    }
                }
            } else {
                self.is_filtered = true;
            }
        }

        Ok(())
    }

    async fn save_policy(&mut self, m: &mut dyn Model) -> Result<()> {
        let conn = self
            .pool
            .get()
            .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::PoolError(err)))))?;

        let mut rules = vec![];

        if let Some(ast_map) = m.get_model().get("p") {
            for (ptype, ast) in ast_map {
                let new_rules = ast
                    .get_policy()
                    .into_iter()
                    .filter_map(|x: &Vec<String>| self.save_policy_line(ptype, x));

                rules.extend(new_rules);
            }
        }

        if let Some(ast_map) = m.get_model().get("g") {
            for (ptype, ast) in ast_map {
                let new_rules = ast
                    .get_policy()
                    .into_iter()
                    .filter_map(|x: &Vec<String>| self.save_policy_line(ptype, x));

                rules.extend(new_rules);
            }
        }

        adapter::save_policy(conn, rules)
    }

    async fn add_policy(&mut self, _sec: &str, ptype: &str, rule: Vec<String>) -> Result<bool> {
        let conn = self
            .pool
            .get()
            .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::PoolError(err)))))?;

        if let Some(new_rule) = self.save_policy_line(ptype, &rule) {
            return adapter::add_policy(conn, new_rule);
        }

        Ok(false)
    }

    async fn add_policies(
        &mut self,
        _sec: &str,
        ptype: &str,
        rules: Vec<Vec<String>>,
    ) -> Result<bool> {
        let conn = self
            .pool
            .get()
            .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::PoolError(err)))))?;

        let new_rules = rules
            .iter()
            .filter_map(|x: &Vec<String>| self.save_policy_line(ptype, x))
            .collect::<Vec<NewCasbinRule>>();

        adapter::add_policies(conn, new_rules)
    }

    async fn remove_policy(&mut self, _sec: &str, pt: &str, rule: Vec<String>) -> Result<bool> {
        let conn = self
            .pool
            .get()
            .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::PoolError(err)))))?;

        adapter::remove_policy(conn, pt, rule)
    }

    async fn remove_policies(
        &mut self,
        _sec: &str,
        pt: &str,
        rules: Vec<Vec<String>>,
    ) -> Result<bool> {
        let conn = self
            .pool
            .get()
            .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::PoolError(err)))))?;

        adapter::remove_policies(conn, pt, rules)
    }

    async fn remove_filtered_policy(
        &mut self,
        _sec: &str,
        pt: &str,
        field_index: usize,
        field_values: Vec<String>,
    ) -> Result<bool> {
        if field_index <= 5 && !field_values.is_empty() && field_values.len() >= 6 - field_index {
            let conn = self
                .pool
                .get()
                .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::PoolError(err)))))?;

            adapter::remove_filtered_policy(conn, pt, field_index, field_values)
        } else {
            Ok(false)
        }
    }

    fn is_filtered(&self) -> bool {
        self.is_filtered
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_owned(v: Vec<&str>) -> Vec<String> {
        v.into_iter().map(|x| x.to_owned()).collect()
    }

    #[cfg_attr(feature = "runtime-async-std", async_std::test)]
    #[cfg_attr(feature = "runtime-tokio", tokio::test)]
    async fn test_adapter() {
        use casbin::prelude::*;

        let mut conn_opts = ConnOptions::default();
        conn_opts.set_auth("casbin_rs", "casbin_rs");
        let file_adapter = FileAdapter::new("examples/rbac_policy.csv");

        let m = DefaultModel::from_file("examples/rbac_model.conf")
            .await
            .unwrap();

        let mut e = Enforcer::new(m, file_adapter).await.unwrap();
        let mut adapter = DieselAdapter::new(conn_opts).unwrap();

        assert!(adapter.save_policy(e.get_mut_model()).await.is_ok());

        assert!(adapter
            .remove_policy("", "p", to_owned(vec!["alice", "data1", "read"]))
            .await
            .is_ok());
        assert!(adapter
            .remove_policy("", "p", to_owned(vec!["bob", "data2", "write"]))
            .await
            .is_ok());
        assert!(adapter
            .remove_policy("", "p", to_owned(vec!["data2_admin", "data2", "read"]))
            .await
            .is_ok());
        assert!(adapter
            .remove_policy("", "p", to_owned(vec!["data2_admin", "data2", "write"]))
            .await
            .is_ok());
        assert!(adapter
            .remove_policy("", "g", to_owned(vec!["alice", "data2_admin"]))
            .await
            .is_ok());

        assert!(adapter
            .add_policy("", "p", to_owned(vec!["alice", "data1", "read"]))
            .await
            .is_ok());
        assert!(adapter
            .add_policy("", "p", to_owned(vec!["bob", "data2", "write"]))
            .await
            .is_ok());
        assert!(adapter
            .add_policy("", "p", to_owned(vec!["data2_admin", "data2", "read"]))
            .await
            .is_ok());
        assert!(adapter
            .add_policy("", "p", to_owned(vec!["data2_admin", "data2", "write"]))
            .await
            .is_ok());

        assert!(adapter
            .remove_policies(
                "",
                "p",
                vec![
                    to_owned(vec!["alice", "data1", "read"]),
                    to_owned(vec!["bob", "data2", "write"]),
                    to_owned(vec!["data2_admin", "data2", "read"]),
                    to_owned(vec!["data2_admin", "data2", "write"]),
                ]
            )
            .await
            .is_ok());

        assert!(adapter
            .add_policies(
                "",
                "p",
                vec![
                    to_owned(vec!["alice", "data1", "read"]),
                    to_owned(vec!["bob", "data2", "write"]),
                    to_owned(vec!["data2_admin", "data2", "read"]),
                    to_owned(vec!["data2_admin", "data2", "write"]),
                ]
            )
            .await
            .is_ok());

        assert!(adapter
            .add_policy("", "g", to_owned(vec!["alice", "data2_admin"]))
            .await
            .is_ok());

        assert!(adapter
            .remove_policy("", "p", to_owned(vec!["alice", "data1", "read"]))
            .await
            .is_ok());
        assert!(adapter
            .remove_policy("", "p", to_owned(vec!["bob", "data2", "write"]))
            .await
            .is_ok());
        assert!(adapter
            .remove_policy("", "p", to_owned(vec!["data2_admin", "data2", "read"]))
            .await
            .is_ok());
        assert!(adapter
            .remove_policy("", "p", to_owned(vec!["data2_admin", "data2", "write"]))
            .await
            .is_ok());
        assert!(adapter
            .remove_policy("", "g", to_owned(vec!["alice", "data2_admin"]))
            .await
            .is_ok());

        assert!(!adapter
            .remove_policy(
                "",
                "g",
                to_owned(vec!["alice", "data2_admin", "not_exists"])
            )
            .await
            .unwrap());

        assert!(adapter
            .add_policy("", "g", to_owned(vec!["alice", "data2_admin"]))
            .await
            .is_ok());
        assert!(adapter
            .add_policy("", "g", to_owned(vec!["alice", "data2_admin"]))
            .await
            .is_err());

        assert!(!adapter
            .remove_filtered_policy(
                "",
                "g",
                0,
                to_owned(vec!["alice", "data2_admin", "not_exists"]),
            )
            .await
            .unwrap());

        assert!(adapter
            .remove_filtered_policy("", "g", 0, to_owned(vec!["alice", "data2_admin"]))
            .await
            .is_ok());

        assert!(adapter
            .add_policy(
                "",
                "g",
                to_owned(vec!["alice", "data2_admin", "domain1", "domain2"]),
            )
            .await
            .is_ok());
        assert!(adapter
            .remove_filtered_policy(
                "",
                "g",
                1,
                to_owned(vec!["data2_admin", "domain1", "domain2"]),
            )
            .await
            .is_ok());

        // shadow the previous enforcer
        let mut e = Enforcer::new(
            "examples/rbac_with_domains_model.conf",
            "examples/rbac_with_domains_policy.csv",
        )
        .await
        .unwrap();

        assert!(adapter.save_policy(e.get_mut_model()).await.is_ok());
        e.set_adapter(adapter).await.unwrap();

        let filter = Filter {
            p: vec!["", "domain1"],
            g: vec!["", "", "domain1"],
        };

        e.load_filtered_policy(filter).await.unwrap();
        assert!(e
            .enforce(&["alice", "domain1", "data1", "read"])
            .await
            .unwrap());
        assert!(e
            .enforce(&["alice", "domain1", "data1", "write"])
            .await
            .unwrap());
        assert!(!e
            .enforce(&["alice", "domain1", "data2", "read"])
            .await
            .unwrap());
        assert!(!e
            .enforce(&["alice", "domain1", "data2", "write"])
            .await
            .unwrap());
        assert!(!e
            .enforce(&["bob", "domain2", "data2", "read"])
            .await
            .unwrap());
        assert!(!e
            .enforce(&["bob", "domain2", "data2", "write"])
            .await
            .unwrap());
    }
}
