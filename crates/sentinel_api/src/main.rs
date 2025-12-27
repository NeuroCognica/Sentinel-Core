use actix_web::{web, App, HttpServer};
use sentinel_api::middleware::envelope_digest::EnvelopeDigestMiddleware;
use sentinel_store::FileEventStore;
use std::sync::Mutex;

// Use the library crate's exported items rather than declaring a local `lib` module.
// `lib.rs` is compiled as the library target; refer to it via the crate name.

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let store = FileEventStore::open("./sentinel_events.log").expect("open store");
    let store = web::Data::new(Mutex::new(store));

    let bind = std::env::var("SENTINEL_BIND").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    println!("Listening on http://{}", bind);

    HttpServer::new(move || {
        App::new()
            .wrap(EnvelopeDigestMiddleware)
            .app_data(store.clone())
            .service(sentinel_api::health)
            .service(sentinel_api::genesis)
            .service(sentinel_api::auth_challenge)
            .service(sentinel_api::auth_login)
            .service(sentinel_api::policy_evaluate)
    })
    .bind(bind)?
    .run()
    .await
}
