use serde::{Deserialize, Serialize};


#[derive(Serialize, Deserialize, Debug, sqlx::FromRow)]
pub struct LoginReq {
    pub username: String,
    pub password: String,
}