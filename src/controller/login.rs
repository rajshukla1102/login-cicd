use axum::{http::status, response::Response, Extension, Json};
use hyper::Body;
use serde_json::json;
use sqlx::PgPool;

use crate::model::login::LoginReq;


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
}
