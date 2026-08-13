use mst5_client::{kind, op, Client, ClientOptions, RequestOptions, Value};
use std::io;
use std::net::TcpListener;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use x25519_dalek::{PublicKey, StaticSecret};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_server_multiplex_cancel_and_reuse() -> io::Result<()> {
    let mut private_bytes = [0u8; 32];
    getrandom::fill(&mut private_bytes).map_err(|error| io::Error::other(error.to_string()))?;
    let private = StaticSecret::from(private_bytes);
    let public = PublicKey::from(&private);
    std::env::set_var("CRYPT_SERVER_PRIVATE_KEY_B64", base64(&private_bytes));
    std::env::set_var("CRYPT_SERVER_PUBLIC_KEY_B64", base64(public.as_bytes()));
    let node_secret = format!("mst5-client-node-{}", now_ms());
    std::env::set_var("NODE_SECRET", &node_secret);
    let address = free_address()?;
    let server_address = address.clone();
    std::thread::spawn(move || {
        micromsg::serve_async(&server_address, micromsg::App::new()).expect("interop MST5 server");
    });
    wait_for_server(&address).await?;
    start_call_node(&address).await?;

    let client = Client::connect(&format!("tcp://{address}"), &base64(public.as_bytes())).await?;
    let auth = client.authenticate_info("").await?;
    assert_eq!(auth.principal_type, "anonymous");
    assert!(client.is_anonymous());
    assert!(!client.is_authenticated());
    assert_ne!(client.features() & mst5_client::feature::MULTIPLEX, 0);
    assert!(!client
        .server_hello()
        .connection_id
        .as_deref()
        .unwrap_or("")
        .is_empty());

    let username = format!("mst5_client_{}", now_ms());
    let registered = client.register(&username, "password123", None).await?;
    assert_eq!(registered.user.username.as_deref(), Some(username.as_str()));
    assert!(client.is_authenticated());
    assert_eq!(
        client.auth_info().and_then(|info| info.principal_id),
        Some(registered.user.id.clone())
    );

    let slow = client.clone();
    let fast = client.clone();
    let (updates, me, ping) =
        tokio::join!(slow.updates(None, Some(1)), fast.get_me(), client.ping(),);
    assert!(updates.is_ok());
    assert_eq!(me?.user.username.as_deref(), Some(username.as_str()));
    ping?;

    let payload = Value::map([("query", Value::from("timeout=2"))]).encode_cbor();
    let deadline = now_ms() + 50;
    let timed_out = client
        .request_cbor_with_options(
            kind::QUERY,
            op::SYNC,
            &payload,
            RequestOptions::default().with_deadline_ms(deadline),
        )
        .await
        .expect_err("long poll must hit the client deadline");
    assert_eq!(timed_out.kind(), io::ErrorKind::TimedOut);

    // CANCEL must not corrupt record boundaries or make the connection unusable.
    let me = client.get_me().await?;
    assert_eq!(me.user.username.as_deref(), Some(username.as_str()));

    let nonce = [0x5a; 16];
    let first_payload = Value::map([("name", Value::from("MST5 idempotent"))]).encode_cbor();
    let first = client
        .request_cbor_with_options(
            kind::COMMAND,
            op::SET_NAME,
            &first_payload,
            RequestOptions::default().with_request_nonce(nonce),
        )
        .await?;
    let replay = client
        .request_cbor_with_options(
            kind::COMMAND,
            op::SET_NAME,
            &first_payload,
            RequestOptions::default().with_request_nonce(nonce),
        )
        .await?;
    assert_ne!(first.id, replay.id);
    assert_eq!(first.payload, replay.payload);

    let conflict_payload = Value::map([("name", Value::from("different"))]).encode_cbor();
    let conflict = client
        .request_cbor_with_options(
            kind::COMMAND,
            op::SET_NAME,
            &conflict_payload,
            RequestOptions::default().with_request_nonce(nonce),
        )
        .await?;
    let conflict = conflict
        .api_error()?
        .expect("nonce reuse with another payload must be a structured error");
    assert_eq!(conflict.code, "IDEMPOTENCY_CONFLICT");
    assert!(conflict.trace_id.is_some());

    let unknown = client.query_value(64, Value::Map(Vec::new())).await?;
    let unknown = unknown
        .into_api_result()
        .expect_err("unknown opcode must return a structured error");
    assert_eq!(unknown.status, 404);
    assert_eq!(unknown.code, "NOT_FOUND");

    voice_round_trip(&address, &base64(public.as_bytes()), &client, &username).await?;
    client.close().await?;

    let invalid_pin = base64(&[0x33; 32]);
    let valid_pin = base64(public.as_bytes());
    let rotated = Client::connect_with_public_keys(
        &format!("tcp://{address}"),
        &[invalid_pin.as_str(), valid_pin.as_str()],
        ClientOptions::default(),
    )
    .await?;
    rotated.authenticate("").await?;
    rotated.close().await?;

    media_node_round_trip().await?;
    Ok(())
}

async fn voice_round_trip(
    address: &str,
    public_key: &str,
    first: &Client,
    first_username: &str,
) -> io::Result<()> {
    let second = Client::connect(&format!("tcp://{address}"), public_key).await?;
    let second_username = format!("mst5_voice_{}", now_ms());
    second
        .register(&second_username, "password123", None)
        .await?;

    let first_ticket = first
        .command(
            op::VOICE_TICKET,
            Value::map([("peer", Value::from(second_username.as_str()))]),
        )
        .await?
        .into_result()?;
    let second_ticket = second
        .command(
            op::VOICE_TICKET,
            Value::map([("peer", Value::from(first_username))]),
        )
        .await?
        .into_result()?;

    let (first_endpoint, first_key, first_ticket) = voice_connection(&first_ticket)?;
    let (second_endpoint, second_key, second_ticket) = voice_connection(&second_ticket)?;

    let first_voice = Client::connect_voice(&first_endpoint, &first_key, &first_ticket).await?;
    assert!(
        Client::connect_voice(&first_endpoint, &first_key, &first_ticket)
            .await
            .is_err(),
        "voice tickets must be single-use"
    );
    let second_voice = Client::connect_voice(&second_endpoint, &second_key, &second_ticket).await?;
    first_voice.send(b"mst5 voice frame").await?;
    let received = tokio::time::timeout(Duration::from_secs(2), second_voice.recv())
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "voice frame was not relayed"))??;
    assert_eq!(received, b"mst5 voice frame");
    first_voice.close().await?;
    second_voice.close().await?;
    second.close().await?;
    Ok(())
}

fn voice_connection(value: &Value) -> io::Result<(String, String, String)> {
    let required = |name: &str| {
        value
            .get(name)
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, format!("missing voice {name}"))
            })
    };
    Ok((
        required("endpoint")?,
        required("server_public_key")?,
        required("ticket")?,
    ))
}

async fn start_call_node(main_address: &str) -> io::Result<()> {
    let mut private_bytes = [0u8; 32];
    getrandom::fill(&mut private_bytes).map_err(|error| io::Error::other(error.to_string()))?;
    let private = StaticSecret::from(private_bytes);
    let public = PublicKey::from(&private);
    let public_b64 = base64(public.as_bytes());
    std::env::set_var("CALL_NODE_PRIVATE_KEY_B64", base64(&private_bytes));

    let address = free_address()?;
    let endpoint = format!("tcp://{address}");
    let server_address = address.clone();
    std::thread::spawn(move || {
        micromsg::serve_call_node(
            &server_address,
            "mst5-client-interop",
            micromsg::CallNodeHub::new(),
        )
        .expect("interop MST5 call node");
    });
    wait_for_server(&address).await?;
    let registration = format!(
        r#"{{"id":"mst5-client-interop","type":"call","endpoint":"{endpoint}","public_key":"{public_b64}","traffic_capacity_bps":1000000,"traffic_bps":0,"traffic_percent":0}}"#
    );
    micromsg::register_worker_node(&format!("tcp://{main_address}"), &registration)
}

async fn media_node_round_trip() -> io::Result<()> {
    let mut private_bytes = [0u8; 32];
    getrandom::fill(&mut private_bytes).map_err(|error| io::Error::other(error.to_string()))?;
    let private = StaticSecret::from(private_bytes);
    let public = PublicKey::from(&private);
    let public_b64 = base64(public.as_bytes());
    let node_secret = format!("mst5-client-test-{}", now_ms());
    std::env::set_var("FILE_NODE_PRIVATE_KEY_B64", base64(&private_bytes));
    std::env::set_var("FILE_NODE_ID", "mst5-client-interop");
    std::env::set_var("NODE_SECRET", &node_secret);

    let address = free_address()?;
    let server_address = address.clone();
    let root = std::env::temp_dir().join(format!("mst5-client-media-{}", now_ms()));
    let server_root = root.clone();
    std::thread::spawn(move || {
        micromsg::serve_file_node(&server_address, server_root).expect("interop MST5 media node");
    });
    wait_for_server(&address).await?;
    let endpoint = format!("tcp://{address}");
    let file_id = "0123456789abcdef0123456789abcdef";
    let payload: Vec<u8> = (0usize..(256 * 1024 + 17))
        .map(|index| (index.wrapping_mul(31) % 251) as u8)
        .collect();

    let upload = Client::connect_media_internal(&endpoint, &public_b64, &node_secret).await?;
    let mut source = payload.as_slice();
    upload
        .upload_media(file_id, payload.len() as u64, &mut source)
        .await?;

    let stat = Client::connect_media_internal(&endpoint, &public_b64, &node_secret).await?;
    assert_eq!(stat.media_stat(file_id).await?, payload.len() as u64);

    let download = Client::connect_media_internal(&endpoint, &public_b64, &node_secret).await?;
    let mut received = Vec::new();
    assert_eq!(
        download
            .download_media(file_id, payload.len() as u64, &mut received)
            .await?,
        payload.len() as u64
    );
    assert_eq!(received, payload);

    let health = Client::connect_media_internal(&endpoint, &public_b64, &node_secret).await?;
    health.media_health().await?;

    let delete = Client::connect_media_internal(&endpoint, &public_b64, &node_secret).await?;
    delete.media_delete(file_id).await?;
    assert!(!root.join(file_id).exists());
    Ok(())
}

fn free_address() -> io::Result<String> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?.to_string();
    drop(listener);
    Ok(address)
}

async fn wait_for_server(address: &str) -> io::Result<()> {
    for _ in 0..50 {
        if tokio::net::TcpStream::connect(address).await.is_ok() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "interop server did not start",
    ))
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let first = chunk[0];
        let second = *chunk.get(1).unwrap_or(&0);
        let third = *chunk.get(2).unwrap_or(&0);
        output.push(TABLE[(first >> 2) as usize] as char);
        output.push(TABLE[(((first & 3) << 4) | (second >> 4)) as usize] as char);
        if chunk.len() > 1 {
            output.push(TABLE[(((second & 15) << 2) | (third >> 6)) as usize] as char);
        } else {
            output.push('=');
        }
        if chunk.len() > 2 {
            output.push(TABLE[(third & 63) as usize] as char);
        } else {
            output.push('=');
        }
    }
    output
}
