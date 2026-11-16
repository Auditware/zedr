#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    zedr_control_server::server::run(None).await
}
