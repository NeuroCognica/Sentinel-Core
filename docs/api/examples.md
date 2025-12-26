# API Examples

## GET /health

curl -sS -X GET http://127.0.0.1:8080/health

Response:
```
ok
```

## POST /genesis

Request JSON:
```json
{
  "actor_id": "<uuid>",
  "key_id": "<uuid>",
  "public_key": "<hex-encoded-ed25519-public-key>",
  "human_handle": "admin@example.com"
}
```

Example curl:
```bash
curl -X POST http://127.0.0.1:8080/genesis \
  -H "Content-Type: application/json" \
  -d '{"actor_id":"00000000-0000-0000-0000-000000000000","key_id":"00000000-0000-0000-0000-000000000001","public_key":"<hex>","human_handle":"admin@example.com"}'
```

Success response JSON:
```json
{
  "result": "genesis completed",
  "actor_id": "00000000-0000-0000-0000-000000000000",
  "key_id": "00000000-0000-0000-0000-000000000001",
  "public_key": "<hex>"
}
```

## POST /auth/challenge

Request JSON:
```json
{
  "actor_id": "<uuid>",
  "key_id": "<uuid>"
}
```

Example curl:
```bash
curl -X POST http://127.0.0.1:8080/auth/challenge \
  -H "Content-Type: application/json" \
  -d '{"actor_id":"00000000-0000-0000-0000-000000000000","key_id":"00000000-0000-0000-0000-000000000001"}'
```

Success response JSON:
```json
{
  "challenge": "<hex-challenge>",
  "expires_at_utc": "2025-12-25T12:34:56Z"
}
```

## POST /auth/login

Build the canonical envelope JSON using `sentinel_core::CanonicalEnvelopeAuthorizationRequest` structure. Example payload fields:

- `actor_id`: UUID
- `key_id`: UUID
- `nonce`: UUID
- `timestamp_utc`: ISO8601 timestamp
- `payload`: {
    "action": "login",
    "scope": "session",
    "intent": "<challenge>"
  }
- `signature`: ed25519 signature bytes (hex or binary as vector)

Example curl (assuming `envelope.json` contains the canonical envelope):
```bash
curl -X POST http://127.0.0.1:8080/auth/login \
  -H "Content-Type: application/json" \
  -d @envelope.json
```

Success response: `Capability` JSON with fields like `capability_id`, `actor_id`, `issued_at_utc`, `expires_at_utc`, `scope`, `actions`, `token_signature`.

Notes:
- Use the `Keystore` utilities in `sentinel_identity` for generating signatures and test keypairs.
- The examples assume the server is running locally on port 8080.
