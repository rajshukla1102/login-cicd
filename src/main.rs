use axum::{ extract::Extension, routing::{get, post}, Router};
use tower_http::cors::CorsLayer;
use sqlx::postgres::PgPoolOptions;
use dotenv::dotenv;
mod model;
mod controller;

#[tokio::main]
async fn main(){
    let cors_layer = CorsLayer::permissive();
    
    dotenv().ok();
    let durl = std::env::var("DATABASE_URL").expect("set DATABASE_URL env variable");

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&durl)
        .await;

    let pool = pool.expect("could not connect to database");        

    let app = Router::new()
        .route("/", get(|| async{"Success"}))
        .route("/login", post(controller::login::get_authenticate))
        .layer(cors_layer)
        .layer(Extension(pool));
    
    let addr: std::net::SocketAddr= std::net::SocketAddr::from(([0,0,0,0],5000));
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .expect("Failed to start server")
}
