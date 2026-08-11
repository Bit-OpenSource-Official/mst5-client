use mst5_client::Client;
use std::env;
use std::io;

#[tokio::main]
async fn main() -> io::Result<()> {
    let endpoint = env::var("MST5_ENDPOINT").unwrap_or_else(|_| "tcp://127.0.0.1:8080".to_string());
    let public_key = env::var("MST5_SERVER_PUBLIC_KEY_B64").map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "MST5_SERVER_PUBLIC_KEY_B64 is required",
        )
    })?;
    let token = env::var("MST5_TOKEN")
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "MST5_TOKEN is required"))?;

    let client = Client::connect_authenticated(&endpoint, &public_key, &token).await?;
    let me = client.get_me().await?;
    println!("id={}", me.user.id);
    println!("username={:?}", me.user.username);

    if let Ok(to) = env::var("MST5_SEND_TO") {
        let text = env::var("MST5_SEND_TEXT").unwrap_or_else(|_| "Hello from MST5".to_string());
        let message = client.send(to, text).await?;
        println!("message_id={}", message.id);
    }

    client.close().await?;
    Ok(())
}
