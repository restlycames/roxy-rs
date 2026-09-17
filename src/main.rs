mod dispatch;
mod rsa;
mod sdksv;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Roxy starting...");

    tokio::try_join!(
        dispatch::run(),
        sdksv::run(),
    )?;

    Ok(())
}