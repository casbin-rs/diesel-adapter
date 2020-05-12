use async_trait::async_trait;
use casbin::{error::AdapterError, Adapter, Error as CasbinError, Filter, Model, Result};
use diesel::{
    self,
    r2d2::{ConnectionManager, Pool},
};
use dotenv::dotenv;

use crate::{actions as adapter, error::*, models::*};

use std::time::Duration;

#[cfg(feature = "runtime-async-std")]
use async_std::task::spawn_blocking;

#[cfg(feature = "runtime-tokio")]
use tokio::task::spawn_blocking;

pub struct DieselAdapter {
    pool: Pool<ConnectionManager<adapter::Connection>>,
    is_filtered: bool,
}

pub const TABLE_NAME: &str = "casbin_rules";

impl<'a> DieselAdapter {
    pub fn new() -> Result<Self> {
        dotenv().ok();
        let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL is required");
        let pool_size: u32 = std::env::var("POOL_SIZE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(8);
        let manager = ConnectionManager::new(database_url);
        let pool = Pool::builder()
            .connection_timeout(Duration::from_secs(10))
            .max_size(pool_size)
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
}

pub(crate) fn save_policy_line(ptype: &str, rule: &[String]) -> Option<NewCasbinRule> {
    if ptype.trim().is_empty() || rule.is_empty() {
        return None;
    }

    let mut new_rule = NewCasbinRule {
        ptype: ptype.to_owned(),
        v0: "".to_owned(),
        v1: "".to_owned(),
        v2: "".to_owned(),
        v3: "".to_owned(),
        v4: "".to_owned(),
        v5: "".to_owned(),
    };

    new_rule.v0 = rule[0].to_owned();

    if rule.len() > 1 {
        new_rule.v1 = rule[1].to_owned();
    }

    if rule.len() > 2 {
        new_rule.v2 = rule[2].to_owned();
    }

    if rule.len() > 3 {
        new_rule.v3 = rule[3].to_owned();
    }

    if rule.len() > 4 {
        new_rule.v4 = rule[4].to_owned();
    }

    if rule.len() > 5 {
        new_rule.v5 = rule[5].to_owned();
    }

    Some(new_rule)
}

pub(crate) fn load_policy_line(casbin_rule: &CasbinRule) -> Option<Vec<String>> {
    if casbin_rule.ptype.chars().next().is_some() {
        return normalize_policy(casbin_rule);
    }

    None
}

pub(crate) fn load_filtered_policy_line(
    casbin_rule: &CasbinRule,
    f: &Filter,
) -> Option<(bool, Vec<String>)> {
    if let Some(sec) = casbin_rule.ptype.chars().next() {
        if let Some(policy) = normalize_policy(casbin_rule) {
            let mut is_filtered = true;
            if sec == 'p' {
                for (i, rule) in f.p.iter().enumerate() {
                    if !rule.is_empty() && rule != &policy[i] {
                        is_filtered = false
                    }
                }
            } else if sec == 'g' {
                for (i, rule) in f.g.iter().enumerate() {
                    if !rule.is_empty() && rule != &policy[i] {
                        is_filtered = false
                    }
                }
            } else {
                return None;
            }
            return Some((is_filtered, policy));
        }
    }

    None
}

fn normalize_policy(casbin_rule: &CasbinRule) -> Option<Vec<String>> {
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

#[async_trait]
impl Adapter for DieselAdapter {
    async fn load_policy(&self, m: &mut dyn Model) -> Result<()> {
        let conn = self
            .pool
            .get()
            .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::PoolError(err)))))?;

        #[cfg(feature = "runtime-tokio")]
        let rules = spawn_blocking(move || adapter::load_policy(conn))
            .await
            .map_err(|e| casbin::error::AdapterError(Box::new(e)))??;

        #[cfg(feature = "runtime-async-std")]
        let rules = spawn_blocking(move || adapter::load_policy(conn)).await?;

        for casbin_rule in &rules {
            let rule = load_policy_line(casbin_rule);

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

        #[cfg(feature = "runtime-tokio")]
        let rules = spawn_blocking(move || adapter::load_policy(conn))
            .await
            .map_err(|e| casbin::error::AdapterError(Box::new(e)))??;

        #[cfg(feature = "runtime-async-std")]
        let rules = spawn_blocking(move || adapter::load_policy(conn)).await?;

        for casbin_rule in &rules {
            let rule = load_filtered_policy_line(casbin_rule, &f);

            if let Some((is_filtered, rule)) = rule {
                if is_filtered {
                    self.is_filtered = is_filtered;
                    if let Some(ref sec) = casbin_rule.ptype.chars().next().map(|x| x.to_string()) {
                        if let Some(t1) = m.get_mut_model().get_mut(sec) {
                            if let Some(t2) = t1.get_mut(&casbin_rule.ptype) {
                                t2.get_mut_policy().insert(rule);
                            }
                        }
                    }
                }
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
                    .filter_map(|x: &Vec<String>| save_policy_line(ptype, x));

                rules.extend(new_rules);
            }
        }

        if let Some(ast_map) = m.get_model().get("g") {
            for (ptype, ast) in ast_map {
                let new_rules = ast
                    .get_policy()
                    .into_iter()
                    .filter_map(|x: &Vec<String>| save_policy_line(ptype, x));

                rules.extend(new_rules);
            }
        }

        #[cfg(feature = "runtime-tokio")]
        {
            spawn_blocking(move || adapter::save_policy(conn, rules))
                .await
                .map_err(|e| casbin::error::AdapterError(Box::new(e)))?
        }
        #[cfg(feature = "runtime-async-std")]
        {
            spawn_blocking(move || adapter::save_policy(conn, rules)).await
        }
    }

    async fn add_policy(&mut self, _sec: &str, ptype: &str, rule: Vec<String>) -> Result<bool> {
        let conn = self
            .pool
            .get()
            .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::PoolError(err)))))?;
        let ptype_c = ptype.to_string();

        #[cfg(feature = "runtime-tokio")]
        {
            spawn_blocking(move || {
                if let Some(new_rule) = save_policy_line(&ptype_c, &rule) {
                    return adapter::add_policy(conn, new_rule);
                }
                Ok(false)
            })
            .await
            .map_err(|e| casbin::error::AdapterError(Box::new(e)))?
        }

        #[cfg(feature = "runtime-async-std")]
        {
            spawn_blocking(move || {
                if let Some(new_rule) = save_policy_line(&ptype_c, &rule) {
                    return adapter::add_policy(conn, new_rule);
                }
                Ok(false)
            })
            .await
        }
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
        let ptype_c = ptype.to_string();

        #[cfg(feature = "runtime-tokio")]
        {
            spawn_blocking(move || {
                let new_rules = rules
                    .iter()
                    .filter_map(|x: &Vec<String>| save_policy_line(&ptype_c, x))
                    .collect::<Vec<NewCasbinRule>>();
                adapter::add_policies(conn, new_rules)
            })
            .await
            .map_err(|e| casbin::error::AdapterError(Box::new(e)))?
        }

        #[cfg(feature = "runtime-async-std")]
        {
            spawn_blocking(move || {
                let new_rules = rules
                    .iter()
                    .filter_map(|x: &Vec<String>| save_policy_line(&ptype_c, x))
                    .collect::<Vec<NewCasbinRule>>();
                adapter::add_policies(conn, new_rules)
            })
            .await
        }
    }

    async fn remove_policy(&mut self, _sec: &str, pt: &str, rule: Vec<String>) -> Result<bool> {
        let conn = self
            .pool
            .get()
            .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::PoolError(err)))))?;
        let ptype_c = pt.to_string();

        #[cfg(feature = "runtime-tokio")]
        {
            spawn_blocking(move || adapter::remove_policy(conn, &ptype_c, rule))
                .await
                .map_err(|e| casbin::error::AdapterError(Box::new(e)))?
        }

        #[cfg(feature = "runtime-async-std")]
        {
            spawn_blocking(move || adapter::remove_policy(conn, &ptype_c, rule)).await
        }
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
        let ptype_c = pt.to_string();

        #[cfg(feature = "runtime-tokio")]
        {
            spawn_blocking(move || adapter::remove_policies(conn, &ptype_c, rules))
                .await
                .map_err(|e| casbin::error::AdapterError(Box::new(e)))?
        }

        #[cfg(feature = "runtime-async-std")]
        {
            spawn_blocking(move || adapter::remove_policies(conn, &ptype_c, rules)).await
        }
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
            let ptype_c = pt.to_string();

            #[cfg(feature = "runtime-tokio")]
            {
                spawn_blocking(move || {
                    adapter::remove_filtered_policy(conn, &ptype_c, field_index, field_values)
                })
                .await
                .map_err(|e| casbin::error::AdapterError(Box::new(e)))?
            }

            #[cfg(feature = "runtime-async-std")]
            {
                spawn_blocking(move || {
                    adapter::remove_filtered_policy(conn, &ptype_c, field_index, field_values)
                })
                .await
            }
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

        let file_adapter = FileAdapter::new("examples/rbac_policy.csv");

        let m = DefaultModel::from_file("examples/rbac_model.conf")
            .await
            .unwrap();

        let mut e = Enforcer::new(m, file_adapter).await.unwrap();
        let mut adapter = DieselAdapter::new().unwrap();

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
