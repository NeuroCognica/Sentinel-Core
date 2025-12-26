use actix_web::{web, App, HttpServer};
use sentinel_store::FileEventStore;
use std::sync::Mutex;

mod lib;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let store = FileEventStore::open("./sentinel_events.log").expect("open store");
    let store = web::Data::new(Mutex::new(store));

    let bind = std::env::var("SENTINEL_BIND").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    println!("Listening on http://{}", bind);

    HttpServer::new(move || {
        App::new()
            .app_data(store.clone())
            .service(lib::health)
            .service(lib::genesis)
            .service(lib::auth_challenge)
            .service(lib::auth_login)
    })
    .bind(bind)?
    .run()
    .await
}
