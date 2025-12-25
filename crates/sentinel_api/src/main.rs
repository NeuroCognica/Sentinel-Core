use actix_web::{get, web, App, HttpServer, Responder, HttpResponse};
use std::panic;
use std::sync::Mutex;
use sentinel_store::{FileEventStore, EventStore, EventRecord, EventKind};
use uuid::Uuid;
use chrono::Utc;
use serde_json::json;


#[get("/health")]
async fn health(store: web::Data<Mutex<FileEventStore>>) -> impl Responder {
    let mut store = store.lock().unwrap();
    let event = EventRecord {
        event_id: Uuid::new_v4(),
        timestamp_utc: Utc::now(),
        actor: "system".to_string(),
        kind: EventKind::HealthCheck,
        payload: json!({}),
        prev_hash: None,
        hash: "UNHASHED".to_string(),
    };
    match store.append(event) {
        Ok(_) => HttpResponse::Ok().body("ok"),
        Err(e) => HttpResponse::InternalServerError().body(format!("event append failed: {e:?}")),
    }
}

#[actix_web::main]
async fn main() {
    // Set a panic hook to log any panics
    panic::set_hook(Box::new(|info| {
        eprintln!("FATAL: panic occurred: {info}");
    }));

    println!("sentinel_api booting");
    let store = match FileEventStore::open("./sentinel_events.log") {
        Ok(s) => s,
        Err(e) => {
            eprintln!("FATAL: could not open event log: {e:?}");
            std::process::exit(1);
        }
    };
    let store = web::Data::new(Mutex::new(store));

    let server = HttpServer::new(move || {
        App::new()
            .app_data(store.clone())
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
