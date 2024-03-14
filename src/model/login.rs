use serde::{Deserialize, Serialize};


#[derive(Serialize, Deserialize, Debug, sqlx::FromRow)]
pub struct LoginReq {
    pub username: String,
    pub password: String,
}

#[derive(Serialize, Deserialize, Debug, sqlx::FromRow)]
pub struct Order {
    pub orderid: String,
    pub ordernumber: String,
    pub accounts_payment_approval: String,
    pub accounts_approval_date: String,
    pub accounts_payment_desc: String,
    pub accounts_user: i32,
    pub accounts_invoiceamt: f64,
    pub accounts_receiptamt: f64,
    pub acc_approval_ata: String,
    pub accounts_currencyint: String,
    pub accounts_invoiceamt_currencyint: f64,
    pub accounts_receiptamt_currencyint: f64,
    pub accounts_chargedate: String,
}
