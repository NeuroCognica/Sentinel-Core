use actix_web::{get, App, HttpServer, Responder};
use std::panic;

#[get("/health")]
async fn health() -> impl Responder {
    "ok"
}

#[actix_web::main]
async fn main() {
    // Set a panic hook to log any panics
    panic::set_hook(Box::new(|info| {
        eprintln!("FATAL: panic occurred: {info}");
    }));

    println!("sentinel_api booting");
    let server = HttpServer::new(|| {
        App::new()
            .service(health)
    })
    .bind(("127.0.0.1", 8080));

    let server = match server {
        Ok(s) => s,
        Err(e) => {
            eprintln!("FATAL: failed to bind 127.0.0.1:8080: {e}");
            std::process::exit(1);
        }
    };

    println!("sentinel_api listening on 127.0.0.1:8080");
    if let Err(e) = server.run().await {
        eprintln!("FATAL: server crashed: {e}");
        std::process::exit(1);
    }
}
