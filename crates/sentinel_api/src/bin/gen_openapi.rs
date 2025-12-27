#[cfg(feature = "openapi")]
fn main() {
    // Generate merged OpenAPI JSON and print to stdout
    let v = sentinel_api::openapi::generate_openapi_json();
    match serde_json::to_string_pretty(&v) {
        Ok(s) => println!("{}", s),
        Err(e) => {
            eprintln!("failed to serialize openapi json: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(not(feature = "openapi"))]
fn main() {
    eprintln!("openapi feature not enabled; build with --features openapi");
    std::process::exit(1);
}
