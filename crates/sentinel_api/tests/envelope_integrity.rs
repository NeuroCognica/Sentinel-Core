use actix_web::{test, App, web, HttpResponse, Responder, HttpMessage};
use serde_json::json;
use tempfile::TempDir;
use sentinel_api::middleware::envelope_digest::{compute_envelope_digest_hex, EnvelopeDigestMiddleware};

async fn echo(req: actix_web::HttpRequest) -> impl Responder {
    if let Some(meta) = req.extensions().get::<sentinel_api::middleware::envelope_digest::VerifiedEnvelopeMeta>() {
        HttpResponse::Ok().json(json!({ "digest": meta.envelope_digest }))
    } else {
        HttpResponse::BadRequest().body("missing verified meta")
    }
}

fn make_envelope(method: &str, path: &str, nonce: &str, body: serde_json::Value) -> serde_json::Value {
    let digest = compute_envelope_digest_hex(method, path, nonce, &body);
    json!({ "v": 1, "method": method, "path": path, "nonce": nonce, "body": body, "digest": digest })
}

#[actix_rt::test]
async fn happy_path_accepts_correct_digest() {
    let tmpdir = TempDir::new().unwrap();
    let log_path = tmpdir.path().join("sentinel_events.log");

    let app = test::init_service(
        App::new()
            .wrap(EnvelopeDigestMiddleware)
            .route("/echo", web::post().to(echo)),
    )
    .await;

    let env = make_envelope("POST", "/echo", "nonce-1", json!({ "x": 1 }));
    let req = test::TestRequest::post().uri("/echo").set_json(&env).to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
}

#[actix_rt::test]
async fn tampered_body_rejected_even_with_same_digest() {
    let app = test::init_service(
        App::new()
            .wrap(EnvelopeDigestMiddleware)
            .route("/echo", web::post().to(echo)),
    )
    .await;

    // compute digest for body {"x":1} but send body {"x":2}
    let good = make_envelope("POST", "/echo", "nonce-2", json!({ "x": 1 }));
    let mut bad = good.clone();
    let mut body = bad.get_mut("body").unwrap().take();
    *bad.get_mut("body").unwrap() = json!({ "x": 2 });

    let req = test::TestRequest::post().uri("/echo").set_json(&bad).to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 400);
}

#[actix_rt::test]
async fn wrong_digest_rejected() {
    let app = test::init_service(
        App::new()
            .wrap(EnvelopeDigestMiddleware)
            .route("/echo", web::post().to(echo)),
    )
    .await;

    let mut env = make_envelope("POST", "/echo", "nonce-3", json!({ "a": 1 }));
    // corrupt digest
    *env.get_mut("digest").unwrap() = json!("deadbeef");

    let req = test::TestRequest::post().uri("/echo").set_json(&env).to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 400);
}

#[actix_rt::test]
async fn missing_digest_rejected() {
    let app = test::init_service(
        App::new()
            .wrap(EnvelopeDigestMiddleware)
            .route("/echo", web::post().to(echo)),
    )
    .await;

    let env = json!({ "v":1, "method":"POST", "path":"/echo", "nonce":"nonce-4", "body": { "x": 5 } });
    let req = test::TestRequest::post().uri("/echo").set_json(&env).to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 400);
}

#[actix_rt::test]
async fn replay_with_new_nonce_rejected_by_digest_mismatch() {
    let app = test::init_service(
        App::new()
            .wrap(EnvelopeDigestMiddleware)
            .route("/echo", web::post().to(echo)),
    )
    .await;

    // digest computed for nonce-old
    let env = make_envelope("POST", "/echo", "nonce-old", json!({ "k": "v" }));
    // replay using a different nonce but same digest
    let mut replay = env.clone();
    *replay.get_mut("nonce").unwrap() = json!("nonce-new");

    let req = test::TestRequest::post().uri("/echo").set_json(&replay).to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 400);
}
