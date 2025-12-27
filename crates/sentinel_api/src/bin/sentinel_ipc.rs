use std::io::{self, BufRead, Write};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
struct Request {
    op: String,
    v: u32,
    #[serde(default)]
    args: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct OkResp<T: Serialize> {
    ok: bool,
    data: T,
}

#[derive(Debug, Serialize)]
struct ErrObj {
    code: String,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct ErrResp {
    ok: bool,
    error: ErrObj,
}

fn main() -> anyhow::Result<()> {
    let stdin = io::stdin();
    let mut stdout = io::stdout();

    for line_res in stdin.lock().lines() {
        let line = match line_res {
            Ok(l) => l,
            Err(_) => break,
        };
        if line.trim().is_empty() {
            continue;
        }

        let req: Request = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                write_err(&mut stdout, "MALFORMED_REQUEST_400", &format!("Invalid request JSON: {e}"), None)?;
                continue;
            }
        };

        let resp_json = match req.op.as_str() {
            "ready" => {
                serde_json::to_string(&OkResp { ok: true, data: serde_json::json!({
                    "ready": true,
                    "policy_digest": "",
                    "ledger_digest": ""
                }) })?
            }
            "submit_envelope" => {
                let _env = req.args.get("envelope").cloned().unwrap_or(serde_json::Value::Null);
                serde_json::to_string(&OkResp { ok: true, data: serde_json::json!({
                    "decision": "allow",
                    "policy_digest": "",
                    "input_digest": "",
                    "envelope_digest": "",
                    "rule_ids": [],
                    "rationale": "ok"
                }) })?
            }
            "submit_proof" => {
                serde_json::to_string(&OkResp { ok: true, data: serde_json::json!({
                    "seal_id": "",
                    "artifact_digest": serde_json::Value::Null,
                    "policy_digest": "",
                    "input_digest": "",
                    "consent_event_id": "",
                    "created_at_utc": ""
                }) })?
            }
            "replay" => {
                serde_json::to_string(&OkResp { ok: true, data: serde_json::json!({
                    "events": [],
                    "next_offset": 0
                }) })?
            }
            _ => {
                serde_json::to_string(&ErrResp {
                    ok: false,
                    error: ErrObj {
                        code: "MALFORMED_ENVELOPE_400".into(),
                        message: format!("Unknown op: {}", req.op),
                        detail: None,
                    },
                })?
            }
        };

        stdout.write_all(resp_json.as_bytes())?;
        stdout.write_all(b"\n")?;
        stdout.flush()?;
    }

    Ok(())
}

fn write_err(stdout: &mut dyn Write, code: &str, msg: &str, detail: Option<serde_json::Value>) -> anyhow::Result<()> {
    let err = ErrResp {
        ok: false,
        error: ErrObj { code: code.into(), message: msg.into(), detail },
    };
    let s = serde_json::to_string(&err)?;
    stdout.write_all(s.as_bytes())?;
    stdout.write_all(b"\n")?;
    stdout.flush()?;
    Ok(())
}
