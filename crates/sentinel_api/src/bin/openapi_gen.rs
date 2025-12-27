#![cfg(feature = "openapi")]
use sentinel_api::openapi::generate_openapi_json;
use serde_json::to_string_pretty;

fn main() {
    let api = generate_openapi_json();
    match to_string_pretty(&api) {
        Ok(s) => println!("{}", s),
        Err(e) => {
            eprintln!("failed to serialize openapi json: {e}");
            std::process::exit(1);
        }
    }
}
