use async_trait::async_trait;
use casbin::{Adapter, Model, Result};
use diesel::{
    self,
    r2d2::{ConnectionManager, Pool},
    RunQueryDsl,
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

        adapter::new(conn).map(|_x| Self { pool })
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
        let conn = self
            .pool
            .get()
            .map_err(|err| Box::new(Error::PoolError(err)) as Box<dyn StdError>)?;

        adapter::remove_policy(conn, pt, rule)
    }

    async fn remove_filtered_policy(
        &self,
        _sec: &str,
        pt: &str,
        field_index: usize,
        field_values: Vec<&str>,
    ) -> Result<bool> {
        if field_index <= 5 && !field_values.is_empty() && field_values.len() <= 6 - field_index {
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

    #[test]
    fn test_adapter() {
        // # Ubuntu
        // sudo apt install libpq-dev libmysqlclient-dev
        //
        // # Deepin
        // sudo apt install libpq-dev libmysql++-dev
        //
        // docker run -itd --restart always -e POSTGRES_USER=casbin_rs -e POSTGRES_PASSWORD=casbin_rs -e POSTGRES_DB=casbin -p 5432:5432 -v /srv/docker/postgresql:/var/lib/postgresql postgres:11;
        // docker run -itd --restart always -e MYSQL_ALLOW_EMPTY_PASSWORD=yes -e MYSQL_USER=casbin_rs -e MYSQL_PASSWORD=casbin_rs -e MYSQL_DATABASE=casbin -p 3306:3306 -v /srv/docker/mysql:/var/lib/mysql mysql:8 --default-authentication-plugin=mysql_native_password;
        //
        //  # Ubuntu
        //  sudo apt install postgresql-client-11 mysql-client-core-8.0
        //
        //  # Deepin
        //  sudo apt install mysql-client postgresql-client-9.6
        //
        //  psql postgres://casbin_rs:casbin_rs@127.0.0.1:5432/casbin;
        //  mysql -h 127.0.0.1 -u casbin_rs -p
        //
        // To run the test against postgresql:
        // cargo test
        //
        // To run the test against mysql:
        // cargo test --no-default-features --features mysql
        //
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
