use super::schema::casbin_rule;

#[derive(Queryable, Identifiable)]
pub(crate) struct CasbinRule {
    pub id: i32,
    pub p_type: String,
    pub v0: String,
    pub v1: String,
    pub v2: String,
    pub v3: String,
    pub v4: String,
    pub v5: String,
}

#[derive(Insertable, Clone)]
#[table_name = "casbin_rule"]
pub(crate) struct NewCasbinRule {
    pub p_type: String,
    pub v0: String,
    pub v1: String,
    pub v2: String,
    pub v3: String,
    pub v4: String,
    pub v5: String,
}
