use axum::{http::status, response::Response, Extension, Json};
use hyper::Body;
use serde_json::json;
use sqlx::PgPool;

use crate::model::login::{LoginReq, Order};


pub async fn get_authenticate(
    Extension(pg_pool): Extension<PgPool>,
    Json(LoginReq { username, password }): Json<LoginReq>,
) -> Result<Response<Body>, Response<Body>> {
        
    let res = sqlx::query(
        r#"SELECT 
        username, password
        from users where username=$1 and password=$2"#,
    )
    .bind(&username)
    .bind(password)
    .fetch_one(&pg_pool)
    .await;

    match res {
        Ok(_user) => {
            let json = json!({
                "username": username,
                "staus": "Authenticated"
            });
            let body = Body::from(serde_json::to_vec(&json).unwrap());
            Ok(Response::builder()
                .status(status::StatusCode::OK)
                .header("Content-Type", "application/json")
                .body(body)
                .unwrap())
        }
        Err(_e) => {
            let json = json!({
                "status": "Failed"
            });
            let body = Body::from(serde_json::to_vec(&json).unwrap());
            Ok(Response::builder()
                .status(status::StatusCode::UNAUTHORIZED)
                .header("Content-Type", "application/json")
                .body(body)
                .unwrap())
        }
    }
}

pub async fn checkfornull(
    Json(query): Json<Order>,
) -> Result<Response<Body>, Response<Body>> {
        if query.ordernumber.is_empty() || query.accounts_payment_approval.is_empty() || query.accounts_approval_date.is_empty() || query.accounts_payment_desc.is_empty() || query.acc_approval_ata.is_empty() || query.accounts_currencyint.is_empty() || query.accounts_chargedate.is_empty(){
            let json = json!({
                "status": "Failed"
            });
            let body = Body::from(serde_json::to_vec(&json).unwrap());
            Ok(Response::builder()
                .status(status::StatusCode::UNAUTHORIZED)
                .header("Content-Type", "application/json")
                .body(body)
                .unwrap())
        } else {
            let json = json!({
                "status": "Success"
            });
            let body = Body::from(serde_json::to_vec(&json).unwrap());
            Ok(Response::builder()
                .status(status::StatusCode::OK)
                .header("Content-Type", "application/json")
                .body(body)
                .unwrap())
        }
    
}


#[cfg(test)]
mod tests {
    use std::env;

    use super::*;
    use axum::{extract::Extension, http::StatusCode};
    use serde_json::Value;
    use sqlx::postgres::PgPoolOptions;    
    use axum::http::Request;
    use hyper::Body;
    use dotenv::dotenv;
    

    #[tokio::test]
    async fn test_get_itemsid_authenticated() {
        dotenv().ok();
        let db_url = env::var("DATABASE_URL").expect("DATABASE_URL not set");
        let test_username = env::var("TEST_USERNAME").expect("TEST_USERNAME not set");
        let test_password = env::var("TEST_PASSWORD").expect("TEST_PASSWORD not set");

        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(&db_url)
            .await
            .expect("Failed to connect to database");

        let _req = Request::post("/")
            .header("Content-Type", "application/json")
            .body(Body::from(format!(r#"{{ "username": "{}", "password": "{}" }}"#, test_username, test_password)))
            .expect("Failed to create request");

        // println!("Request: {:?}", _req);

        let res = get_authenticate(Extension::from(axum::Extension(pool.clone())), Json(LoginReq {
            username: test_username.clone(),
            password: test_password.clone(),
        }))
        .await
        .expect("Handler function failed");

        // println!("Response: {:?}", res);

        assert_eq!(res.status(), StatusCode::OK);

        let body = hyper::body::to_bytes(res.into_body()).await.expect("err");

        
        let body: Value = serde_json::from_slice(&body).expect("err");
        // println!("Response Body: {:?}", body["staus"]);

        assert_eq!(body["staus"].as_str().expect("err"), "Authenticated"); // Updated assertion for the "status" field
        assert_eq!(body["username"].as_str().expect("msg"), test_username);

    }

    #[tokio::test]
    async fn test_get_itemsid_failed() {
        dotenv().ok();
        let db_url = env::var("DATABASE_URL").expect("DATABASE_URL not set");

        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(&db_url)
            .await
            .expect("Failed to connect to the database");

        let _req = Request::post("/")
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{ "username": "invaliduser", "password": "invalidpassword" }"#))
            .expect("Failed to create request");

        let res = get_authenticate(Extension::from(axum::Extension(pool.clone())), Json(LoginReq {
            username: "invaliduser".to_string(),
            password: "invalidpassword".to_string(),
        }))
        .await
        .expect("Handler function failed");

        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        let body = hyper::body::to_bytes(res.into_body()).await.expect("err in response body reading");
        let body: Value = serde_json::from_slice(&body).expect("err");
        println!("Response Body at line 138: {:?}", body["status"]);
        assert_eq!(body["status"].as_str().expect("err"), "Failed");
    }

    #[tokio::test]
    async fn test_checkfornull_failed() {
        let res = checkfornull(Json(Order {
            orderid: 1,
            ordernumber: "".to_string(),
            accounts_payment_approval: "approved".to_string(),
            accounts_approval_date: "2021-01-01".to_string(),
            accounts_payment_desc: "Payment for order 1".to_string(),
            accounts_user: 1,
            accounts_invoiceamt: 100.00,
            accounts_receiptamt: 100.00,
            acc_approval_ata: "2021-01-01".to_string(),
            accounts_currencyint: "USD".to_string(),
            accounts_invoiceamt_currencyint: 100.00,
            accounts_receiptamt_currencyint: 100.00,
            accounts_chargedate: "2021-01-01".to_string(),
        }))
        .await
        .expect("Handler function failed");

        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        let body = hyper::body::to_bytes(res.into_body()).await.expect("err in response body reading");
        let body: Value = serde_json::from_slice(&body).expect("err");
        assert_eq!(body["status"].as_str().expect("err"), "Failed");
    }

    #[tokio::test]
    async fn test_checkfornull_success() {
        let res = checkfornull(Json(Order {
            orderid: 1,
            ordernumber: "ordernumber".to_string(),
            accounts_payment_approval: "approved".to_string(),
            accounts_approval_date: "2021-01-01".to_string(),
            accounts_payment_desc: "Payment for order 1".to_string(),
            accounts_user: 1,
            accounts_invoiceamt: 100.00,
            accounts_receiptamt: 100.00,
            acc_approval_ata: "2021-01-01".to_string(),
            accounts_currencyint: "USD".to_string(),
            accounts_invoiceamt_currencyint: 100.00,
            accounts_receiptamt_currencyint: 100.00,
            accounts_chargedate: "2021-01-01".to_string(),
        }))
        .await
        .expect("Handler function failed");

        assert_eq!(res.status(), StatusCode::OK);

        let body = hyper::body::to_bytes(res.into_body()).await.expect("err in response body reading");
        let body: Value = serde_json::from_slice(&body).expect("err");
        assert_eq!(body["status"].as_str().expect("err"), "Success");
    }
}
