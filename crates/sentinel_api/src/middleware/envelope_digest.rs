use actix_web::{
    body::{BoxBody, MessageBody},
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
    error::ErrorBadRequest,
    http::Method,
    Error, HttpMessage, HttpResponse,
};
use futures_util::future::{ok, LocalBoxFuture, Ready};
use futures_util::StreamExt;
use serde_json::Value;
use std::{collections::BTreeMap, future::ready, rc::Rc};

pub fn canonicalize_json(v: Value) -> Value {
    match v {
        Value::Object(map) => {
            let mut btm: BTreeMap<String, Value> = BTreeMap::new();
            for (k, v) in map {
                btm.insert(k, canonicalize_json(v));
            }
            let mut out = serde_json::Map::new();
            for (k, v) in btm {
                out.insert(k, v);
            }
            Value::Object(out)
        }
        Value::Array(arr) => Value::Array(arr.into_iter().map(canonicalize_json).collect()),
        other => other,
    }
}

pub fn canonical_json_bytes(v: Value) -> Vec<u8> {
    let canon = canonicalize_json(v);
    serde_json::to_vec(&canon).expect("canonical json serialize")
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    let digest = h.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

pub fn compute_envelope_digest_hex(
    method: &str,
    path: &str,
    nonce: &str,
    body: &Value,
) -> String {
    let payload = serde_json::json!({
        "v": 1,
        "method": method,
        "path": path,
        "nonce": nonce,
        "body": canonicalize_json(body.clone()),
    });

    let bytes = canonical_json_bytes(payload);
    sha256_hex(&bytes)
}

#[derive(Clone)]
pub struct EnvelopeDigestMiddleware;

impl<S> Transform<S, ServiceRequest> for EnvelopeDigestMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<BoxBody>, Error = Error> + 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type InitError = ();
    type Transform = EnvelopeDigestMiddlewareService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(EnvelopeDigestMiddlewareService { service: Rc::new(service) })
    }
}

pub struct EnvelopeDigestMiddlewareService<S> {
    service: Rc<S>,
}

#[derive(Clone, Debug)]
pub struct VerifiedEnvelopeMeta {
    pub envelope_digest: String,
    pub nonce: String,
}

impl<S> Service<ServiceRequest> for EnvelopeDigestMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<BoxBody>, Error = Error> + 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    actix_web::dev::forward_ready!(service);

    fn call(&self, mut req: ServiceRequest) -> Self::Future {
        let svc = self.service.clone();

        Box::pin(async move {
            let method = req.method().clone();
            if !(method == Method::POST || method == Method::PUT || method == Method::PATCH) {
                return svc.call(req).await;
            }

            // Read full request payload from the streaming payload
            let mut payload = req.take_payload();
            let mut buf = bytes::BytesMut::new();
            while let Some(chunk) = payload.next().await {
                let chunk = chunk.map_err(|_| ErrorBadRequest("payload read error"))?;
                buf.extend_from_slice(&chunk);
            }
            let bytes = buf.freeze();

            let parsed: Value = match serde_json::from_slice(&bytes) {
                Ok(v) => v,
                Err(_) => {
                    let resp = HttpResponse::BadRequest().body("invalid json").map_into_boxed_body();
                    return Ok(req.into_response(resp));
                }
            };

            let nonce = match parsed.get("nonce").and_then(|v| v.as_str()) {
                Some(s) => s,
                None => {
                    let resp = HttpResponse::BadRequest().body("missing nonce").map_into_boxed_body();
                    return Ok(req.into_response(resp));
                }
            };
            let provided_digest = match parsed.get("digest").and_then(|v| v.as_str()) {
                Some(s) => s,
                None => {
                    let resp = HttpResponse::BadRequest().body("missing digest").map_into_boxed_body();
                    return Ok(req.into_response(resp));
                }
            };
            let body = match parsed.get("body").cloned() {
                Some(b) => b,
                None => {
                    let resp = HttpResponse::BadRequest().body("missing body").map_into_boxed_body();
                    return Ok(req.into_response(resp));
                }
            };

            let path = req.path().to_string();
            let expected = compute_envelope_digest_hex(req.method().as_str(), &path, nonce, &body);

            if !constant_time_eq_hex(provided_digest, &expected) {
                let resp = HttpResponse::BadRequest().body("envelope digest mismatch").map_into_boxed_body();
                return Ok(req.into_response(resp));
            }

            req.extensions_mut().insert(VerifiedEnvelopeMeta {
                envelope_digest: expected.clone(),
                nonce: nonce.to_string(),
            });

            // Replace the request payload with the canonicalized inner body bytes
            let body_bytes = serde_json::to_vec(&body).map_err(|_| ErrorBadRequest("body serialize error"))?;
            req.set_payload(body_bytes.into());

            svc.call(req).await
        })
    }
}

fn constant_time_eq_hex(a: &str, b: &str) -> bool {
    if a.len() != b.len() { return false; }
    let mut diff: u8 = 0;
    for (x, y) in a.bytes().zip(b.bytes()) {
        diff |= x ^ y;
    }
    diff == 0
}
