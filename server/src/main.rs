use tide::{http::headers::HeaderValue, security::{CorsMiddleware, Origin}};

mod rpc;
mod core;

fn setup_logger() {
    let subscriber = tracing_subscriber::FmtSubscriber::builder()
    .with_max_level(tracing::Level::TRACE)
    .finish();

    tracing::subscriber::set_global_default(subscriber)
        .expect("setting default subscriber failed");
}

#[async_std::main]
async fn main() -> tide::Result<()> {
    setup_logger();

    let cors = CorsMiddleware::new() // FIXME used for dev, probably remove later
        .allow_methods("GET, POST, OPTIONS".parse::<HeaderValue>().unwrap())
        .allow_origin(Origin::from("*"))
        .allow_credentials(false);
    
    let mut app = tide::new();
    app.with(cors);
    app.at("/api").post(rpc::rpc);
    app.listen("127.0.0.1:8081").await?;
    Ok(())
}






