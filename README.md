# mst5-client

Complete asynchronous Rust client for the wire-breaking MST5.1 protocol used by MicroMsg / OVE Messenger.

The transport is native async and uses `tokio::net::TcpStream`. The crate does not use an HTTP bridge, OpenSSL, `spawn_blocking`, or synchronous sockets.

## Features

- native MST5 secure transport over TCP
- pinned X25519 server public key
- ChaCha20-Poly1305 encrypted records
- async connect/read/write with Tokio
- mandatory encrypted HELLO feature/version negotiation
- true 64-request multiplexing on one cloneable connection
- MST5 AUTH principals, QUERY, COMMAND, PING/PONG, transport CLOSE, CANCEL and EVENT_BATCH handling
- command idempotency nonces, absolute deadlines and timeout cancellation
- structured API errors and deterministic per-direction record rekeying
- raw DEFLATE support for compressed server responses
- built-in CBOR subset used by the server
- high-level account, messaging, bot, wallet, chat, E2E, media and node methods
- direct media-node upload/download streams with ticket authentication, node pinning and SHA-256 verification
- low-level opcode API remains available

## Dependencies

Runtime dependencies are intentionally small:

```toml
[dependencies]
chacha20poly1305 = { version = "0.10.1", default-features = false, features = ["alloc"] }
getrandom = "0.3.3"
hkdf = { version = "0.12.4", default-features = false }
hmac = { version = "0.12.1", default-features = false }
miniz_oxide = "0.9.1"
sha2 = { version = "0.10.9", default-features = false }
tokio = { version = "1.47", default-features = false, features = ["net", "io-util", "time", "rt", "sync"] }
x25519-dalek = { version = "2.0.1", default-features = false, features = ["getrandom", "reusable_secrets", "zeroize"] }
zeroize = { version = "1.8.1", default-features = false }
```

SHA-256, HMAC-SHA256, HKDF, AEAD, X25519, zeroization and OS randomness use
reviewed crates. Base64, percent encoding, the constrained CBOR codec and MST5
framing remain implemented inside this crate.

For an application using `#[tokio::main]`, enable Tokio runtime/macros in the application itself, for example:

```toml
[dependencies]
mst5-client = { path = "../mst5-client" }
tokio = { version = "1.47", features = ["macros", "rt-multi-thread"] }
```

## Quick start

```rust
use mst5_client::Client;
use std::io;

#[tokio::main]
async fn main() -> io::Result<()> {
	let client = Client::connect_authenticated(
		"tcp://127.0.0.1:8080",
		"BASE64_SERVER_X25519_PUBLIC_KEY",
		"SESSION_TOKEN",
	)
	.await?;

	let me = client.get_me().await?;
	println!("my id: {}", me.user.id);

	let message = client.send("@alice", "Hello").await?;
	println!("message id: {}", message.id);

	client.close().await?;
	Ok(())
}
```

## Recipient identifiers

Methods accepting a user or peer through `ToString` can normally receive the same address forms accepted by the server:

```rust
client.send(123i64, "Hello").await?;
client.send("000000000000007b", "Hello").await?;
client.send("@alice", "Hello").await?;
```

This is also useful with methods such as `add_contact`, `history`, `read_messages`, `wallet_send`, `forward_message`, and `get_e2e_key`.

## Connecting

### Pinned public key as Base64

```rust
let client = Client::connect(endpoint, server_public_key_b64).await?;
client.authenticate(token).await?;
```

### Connect and authenticate in one call

```rust
let client = Client::connect_authenticated(
	endpoint,
	server_public_key_b64,
	token,
)
.await?;
```

### Raw 32-byte pinned public key

```rust
let key: [u8; 32] = load_server_key();
let client = Client::connect_with_key(endpoint, key).await?;
client.authenticate(token).await?;
```

### Pinned-key rotation

During a server-key transition, provide the current and next pins. They are tried
in order and the successfully verified Noise handshake is used:

```rust
let client = Client::connect_with_public_keys(
	endpoint,
	&[current_key_b64, next_key_b64],
	ClientOptions::default(),
)
.await?;
```

## Registration and login

Account bootstrap operations automatically send an empty-token MST5 AUTH if the connection has not been authenticated yet.

The server promotes the current MST5 session to the newly returned token after successful registration, login, or email verification, so the same `Client` can immediately call authenticated methods.

```rust
let client = Client::connect(endpoint, server_public_key_b64).await?;

let auth = client.login("alice", "password").await?;
println!("token: {}", auth.token);

let me = client.get_me().await?;
println!("id: {}", me.user.id);
```

Registration and email authentication:

```rust
let auth = client
	.register("alice", "password", Some("alice@example.com"))
	.await?;

client.start_email_auth("alice@example.com").await?;

let auth = client
	.verify_email_auth("alice@example.com", "123456", None)
	.await?;
```

Email/password login is also available:

```rust
let auth = client
	.login_email("alice@example.com", "password")
	.await?;
```

## Timeouts

`ClientOptions` controls connect, read, and write timeouts independently.

Defaults:

```text
connect_timeout = 10 seconds
read_timeout    = 40 seconds
write_timeout   = 15 seconds
nodelay         = true
```

Custom options:

```rust
use mst5_client::{Client, ClientOptions};
use std::time::Duration;

let options = ClientOptions {
	connect_timeout: Duration::from_secs(5),
	read_timeout: Duration::from_secs(90),
	write_timeout: Duration::from_secs(10),
	nodelay: true,
};

let client = Client::connect_with_options(
	endpoint,
	server_public_key_b64,
	options,
)
.await?;
```

For long polling, configure `read_timeout` longer than the requested `updates(..., timeout_secs)` value. A timeout or dropped request future sends best-effort MST5 CANCEL; it does not tear down the connection.

## Concurrency model

`Client` is cloneable. All clones share one encrypted session, a background reader,
an ID-indexed pending-request map and a serialized record writer. Up to 64 RPCs may
be in flight; responses can complete out of order without an application mutex:

```rust
let (me, chats, wallet) = tokio::join!(
	client.get_me(),
	client.chats(),
	client.wallet(),
);
```

Subscribe before the operation that can produce unsolicited event batches:

```rust
let mut events = client.subscribe_events();
let event = events.recv().await?;
```

## Return types

Frequently used operations return typed values:

| Type | Used by | Important fields |
|---|---|---|
| `AuthResult` | `register`, `login`, `login_email`, `verify_email_auth`, bot token methods | `token`, `user` |
| `Me` | `get_me` | `user`, `cloud_password` |
| `User` | profile convenience methods | `id`, `username`, `name`, `email`, `bot`, privacy fields |
| `Message` | send/edit/favorite/forward/comment methods | `id`, `chat_id`, `from`, `to`, `text`, dates, media, data, reactions |
| `Value` | flexible or server-specific responses | CBOR-compatible structured value |
| `Response` | low-level API | `kind`, `flags`, `status`, `id`, `request_nonce`, `deadline_ms`, raw `payload` |

`Value` supports:

```rust
pub enum Value {
	Null,
	Bool(bool),
	Unsigned(u64),
	Integer(i64),
	Float(f64),
	Bytes(Vec<u8>),
	Text(String),
	Array(Vec<Value>),
	Map(Vec<(String, Value)>),
}
```

## Access legend

The tables below describe server-side account-type restrictions.

| Access | Meaning |
|---|---|
| `Public` | Account bootstrap/recovery flow; can begin through empty-token MST5 AUTH. |
| `Both` | No explicit normal-user-vs-bot rejection on the route. Normal permission/ownership/privacy/balance checks still apply. |
| `Both*` | Both account types can reach the route, but a branch or optional field has an additional restriction. |
| `User` | Server explicitly requires a non-bot user for this operation. |
| `Bot` | Server explicitly requires a bot account. |
| `Node` | Internal node secret/session is required. |
| `System bot` | A fixed built-in system-bot identity is required. |

## Connection and low-level transport API

| Method | Returns | Description |
|---|---|---|
| `Client::connect(endpoint, key_b64).await` | `Client` | Connect with default timeouts and Base64 pinned key. |
| `Client::connect_with_options(...).await` | `Client` | Connect with custom `ClientOptions`. |
| `Client::connect_with_key(endpoint, key).await` | `Client` | Connect with raw `[u8; 32]` pinned key. |
| `Client::connect_with_key_and_options(...).await` | `Client` | Raw key plus custom options. |
| `Client::connect_with_public_keys(...).await` | `Client` | Try an ordered Base64 pin bundle during key rotation. |
| `Client::connect_with_keys(...).await` | `Client` | Try an ordered raw-key pin bundle. |
| `Client::connect_authenticated(...).await` | `Client` | Connect and send MST5 AUTH immediately. |
| `authenticate(token).await` | `()` | Authenticate or replace the current MST5 bearer token. |
| `authenticate_info(token).await` | `AuthInfo` | Authenticate and return principal/scopes/session metadata. |
| `auth_info()` | `Option<AuthInfo>` | Return locally cached metadata from the latest AUTH. |
| `is_anonymous()` | `bool` | Whether AUTH established an anonymous principal. |
| `is_authenticated()` | `bool` | Whether the principal is non-anonymous. |
| `server_hello()` / `features()` | metadata | Inspect the negotiated RPC version, limits and feature bits. |
| `subscribe_events()` | `EventReceiver` | Receive unsolicited EVENT_BATCH frames. |
| `ping().await` | `()` | Send MST5 PING and wait for matching PONG. |
| `close().await` | `()` | Send the encrypted transport CLOSE record and shut down the socket. |
| `query(opcode, query).await` | `Response` | Low-level QUERY using a query string. |
| `query_value(opcode, value).await` | `Response` | Low-level QUERY with explicit CBOR `Value`. |
| `command(opcode, value).await` | `Response` | Low-level COMMAND. |
| `request_cbor(kind, opcode, bytes).await` | `Response` | Lowest-level authenticated CBOR request API. |
| `request_cbor_with_options(...).await` | `Response` | Low-level API with a caller-owned nonce/deadline for safe retries. |

## Account and profile API

| Method | Access | Returns | Description |
|---|---|---|---|
| `register(username, password, email).await` | Public | `AuthResult` | Create a normal account. |
| `login(username, password).await` | Public | `AuthResult` | Login by username/password. |
| `login_email(email, password).await` | Public | `AuthResult` | Login by email/password. |
| `start_email_auth(email).await` | Public | `Value` | Start email code authentication. |
| `verify_email_auth(email, code, cloud_password).await` | Public | `AuthResult` | Complete email authentication. |
| `get_me().await` | Both | `Me` | Return the current account. |
| `delete_account(code).await` | Both* | `Value` | Delete the current account; server-side recovery/account prerequisites still apply. |
| `set_username(username).await` | Both | `User` | Set account username. |
| `set_name(name).await` | Both | `User` | Set display name. |
| `set_description(description).await` | Both | `Value` | Set the current account description. |
| `set_profile_description(profile, description).await` | Both* | `Value` | Edit own profile, an owned bot, or an administered profile when permitted. |
| `set_privacy(message, call, invite).await` | Both | `Value` | Set privacy fields. |

## Contacts, groups and channels

| Method | Access | Returns | Description |
|---|---|---|---|
| `contacts().await` | Both | `Value` | List contacts. |
| `add_contact(user).await` | Both | `Value` | Add a contact. |
| `delete_contact(user).await` | Both | `Value` | Remove a contact. |
| `create_group(title, members).await` | Both | `Value` | Create a group. |
| `create_channel(title, username, members).await` | Both | `Value` | Create a channel. |
| `set_chat_title(chat, title).await` | Both | `Value` | Change group/channel title when permitted. |
| `set_channel_username(chat, username).await` | Both | `Value` | Change channel username when permitted. |
| `set_channel_comments(chat, enabled).await` | Both | `Value` | Enable or disable channel comments. |
| `send_channel_comment(chat, post_id, text, reply_to, client_id).await` | Both | `Message` | Send a channel post comment. |
| `channel_comments(chat, post_id, before, limit).await` | Both | `Value` | Read comments for a channel post. |
| `add_chat_member(chat, user).await` | Both | `Value` | Add a group/channel member when permissions allow it. |
| `remove_chat_member(chat, user).await` | Both | `Value` | Remove a member when permissions allow it. |
| `chats().await` | Both | `Value` | List chats/dialogs. |
| `delete_chat(peer).await` | Both | `Value` | Delete/leave/hide a chat according to server permissions. |
| `ban_user(username).await` | Both | `Value` | Ban a user where supported by the server. |
| `unban_user(username).await` | Both | `Value` | Remove a ban. |
| `history(peer, after, before, limit).await` | Both | `Value` | Read message history. |

Example:

```rust
let chats = client.chats().await?;

let history = client
	.history("@alice", None, None, Some(50))
	.await?;

client.read_messages("@alice").await?;
```

## Sessions and bot management

| Method | Access | Returns | Description |
|---|---|---|---|
| `sessions().await` | Both | `Value` | List account sessions. |
| `revoke_session(id).await` | Both | `Value` | Revoke one session. |
| `revoke_other_sessions().await` | Both | `Value` | Revoke all other sessions. |
| `create_bot(username).await` | Both | `AuthResult` | Create a bot owned by the current account. |
| `reset_bot_token(username).await` | Both* | `AuthResult` | Reset a bot token when current-account ownership rules permit it. |

## Cloud password and E2E

| Method | Access | Returns | Description |
|---|---|---|---|
| `set_cloud_password(password, e2e_backup).await` | Both | `Value` | Set cloud password and optional E2E backup. |
| `reset_cloud_password(email, code).await` | Public / Both | `Value` | Reset/recover cloud password. |
| `set_e2e_key(public_key_b64).await` | Both | `Value` | Register current account E2E public key. |
| `get_e2e_key(user).await` | Both | `Value` | Read another account's E2E public key. |
| `set_e2e_backup(backup).await` | Both | `Value` | Store E2E backup data. |
| `get_e2e_backup().await` | Both | `Value` | Read current account E2E backup. |
| `reset_e2e().await` | Both | `Value` | Reset current account E2E state. |

## Wallet and reactions

| Method | Access | Returns | Description |
|---|---|---|---|
| `wallet().await` | Both | `Value` | Read wallet state. |
| `wallet_send(to, amount, comment, idempotency_key).await` | Both | `Value` | Send DSR. |
| `wallet_history(limit).await` | Both | `Value` | Read wallet transactions. |
| `react(message_id, emoji).await` | Both | `Value` | Set/remove a free reaction. |
| `react_paid(message_id, amount, idempotency_key).await` | Both | `Value` | Add a paid reaction. |

## Calls and voice

| Method | Access | Returns | Description |
|---|---|---|---|
| `call(to, action).await` | User | `Value` | Direct call signaling. Direct calls explicitly reject bots. |
| `create_voice_ticket(peer).await` | Both* | `Value` | Create a voice ticket. Group voice can be reachable by bots; direct user voice rejects bots. |
| `voice_participants(peer).await` | Both | `Value` | List group voice participants. |

## Messaging API

| Method | Access | Returns | Description |
|---|---|---|---|
| `send(to, text).await` | Both | `Message` | Send a simple text message. |
| `send_advanced(request).await` | Both* | `Message` | Advanced send with server-specific fields; bot-only optional fields can be supplied here. |
| `edit_message(id, text).await` | Both | `Message` | Edit text of an existing message. |
| `edit_message_advanced(request).await` | Both* | `Message` | Advanced edit including optional structured fields. |
| `callback(to, message_id, callback).await` | Both | `Value` | Trigger a callback button addressed to a bot. |
| `read_messages(peer).await` | Both | `Value` | Mark peer/chat messages as read. |
| `delete_message(id).await` | Both | `Value` | Delete a message when author/admin rules allow it. |
| `favorite_message(id).await` | Both | `Message` | Copy a message to favorites/self. |
| `forward_message(message_id, to, client_message_id).await` | Both | `Message` | Forward a message. |

Simple send:

```rust
let message = client.send("@alice", "Hello").await?;
println!("{}", message.id);
```

Advanced bot send:

```rust
use mst5_client::Value;

let message = client
	.send_advanced(Value::map([
		("to", Value::from("@alice")),
		("text", Value::from("Choose an action")),
		(
			"buttons",
			Value::Array(vec![Value::map([
				("text", Value::from("OK")),
				("callback", Value::from("ok")),
			])]),
		),
		("idempotency_key", Value::from("event:123:reply")),
	]))
	.await?;
```

`send_advanced()` exists because the server's full send payload contains optional structured fields that would make a minimal convenience signature unnecessarily large.

## Bot updates

| Method | Access | Returns | Description |
|---|---|---|---|
| `updates(after, timeout_secs).await` | Both | `Value` | Long-poll pending updates/events. |
| `ack_updates(ids).await` | Bot | `Value` | Acknowledge update IDs. The server explicitly restricts ACK to bots. |

Typical bot polling loop:

```rust
loop {
	let batch = client.updates(Some(0), Some(30)).await?;

	// Parse/process batch here.
	// Keep the update ids that were processed successfully.
	let processed = vec![1, 2, 3];

	if !processed.is_empty() {
		client.ack_updates(&processed).await?;
	}
}
```

`updates()` intentionally returns `Value` because update payloads are heterogeneous: messages, callbacks, calls, reactions, and other event types can appear in the same stream.

## Media API

| Method | Access | Returns | Description |
|---|---|---|---|
| `media_quote(request).await` | Both | `Value` | Request media upload pricing/quote data. |
| `prepare_message_media(request).await` | Both* | `Value` | Prepare a media send/edit operation. Some structured bot fields are bot-restricted by the server. |
| `commit_message_media(operation_id).await` | Both | `Value` | Commit a prepared media operation. |
| `cancel_message_media(operation_id, client_message_id).await` | Both | `Value` | Cancel a prepared operation. |
| `file_ticket(id).await` | Both | `Value` | Request an authorized file download ticket. |

Media methods intentionally accept/return `Value` because the media workflow contains structured descriptors, upload metadata, and operation-specific fields.

Direct media-node connections use their own pin and credential. A transfer-ticket
connection supports one upload or download; internal node credentials also expose
stat, delete and health operations:

```rust
let media = Client::connect_media(media_endpoint, media_pin, ticket).await?;
media.upload_media(file_id, size, &mut source).await?;

let internal = Client::connect_media_internal(media_endpoint, media_pin, node_secret).await?;
let size = internal.media_stat(file_id).await?;
```

Open a fresh media connection for each transfer or metadata operation, as required
by the MST5.1 media profile.

## OAuth device API

| Method | Access | Returns | Description |
|---|---|---|---|
| `oauth_device_request(user_code).await` | User | `Value` | Inspect an OAuth device authorization request. |
| `oauth_device_decision(user_code, decision).await` | User | `Value` | Approve or reject an OAuth device authorization request. |

The server explicitly rejects bot accounts for these user authorization actions.

## Node and internal API

These methods are not normal application/bot API calls.

| Method | Access | Returns | Description |
|---|---|---|---|
| `nodes_status().await` | Both | `Value` | Read worker-node status visible through the authenticated API. |
| `register_node(request).await` | Node | `Value` | Register/heartbeat an internal worker node. |
| `list_nodes().await` | Node | `Value` | List internal worker nodes. |
| `botfather_execute(event_id, user_id, text).await` | System bot | `Value` | Execute internal BotFather processing. |
| `dastars_credit(user_id, amount, txid).await` | System bot | `Value` | Internal DaStars credit operation. |

## Error handling

High-level methods convert MST5 `ERROR` frames and HTTP-like server status codes into `std::io::Error`. The source error is a structured `ApiError`, so callers can downcast it and inspect stable code, retryability, retry delay, details and trace ID.

For example:

```rust
match client.get_me().await {
	Ok(me) => println!("{}", me.user.id),
	Err(error) => eprintln!("MST5 error: {error}"),
}
```

The current mapping includes common error kinds such as permission denied, not found, timeout, already exists, and invalid input.

For low-level handling, use `Response` directly:

```rust
let response = client.command(opcode, payload).await?;

println!("status = {}", response.status);
println!("error  = {}", response.is_error());
println!("body   = {:?}", response.cbor()?);

if let Err(api_error) = response.into_api_result() {
	eprintln!("{}: {}", api_error.code, api_error.message);
}
```

## Low-level opcode API

All high-level wrappers are built on the same public low-level API, so new server operations can be used without waiting for a convenience wrapper.

```rust
use mst5_client::{op, Client, Value};

let client = Client::connect_authenticated(
	endpoint,
	server_public_key_b64,
	token,
)
.await?;

let response = client
	.command(
		op::SEND,
		Value::map([
			("to", Value::from("@alice")),
			("text", Value::from("Hello")),
		]),
	)
	.await?;

let body = response.into_result()?;
println!("{body:?}");
```

The `op` module exposes the MST5 opcode constants used by the supplied server implementation.

When a caller must retry an uncertain mutation after reconnecting, reuse the
same non-zero nonce only with the exact same opcode and CBOR payload:

```rust
use mst5_client::{kind, RequestOptions};

let options = RequestOptions::default()
	.with_request_nonce(order_nonce)
	.with_deadline_ms(deadline_ms);
let response = client
	.request_cbor_with_options(kind::COMMAND, opcode, &payload, options)
	.await?;
```

## Migrating from the synchronous version

Public method names were preserved where possible. Network operations now need `.await`.

Before:

```rust
let client = Client::connect(endpoint, public_key)?;
client.authenticate(token)?;
let me = client.get_me()?;
client.send("@alice", "Hello")?;
```

Async version:

```rust
let client = Client::connect(endpoint, public_key).await?;
client.authenticate(token).await?;
let me = client.get_me().await?;
client.send("@alice", "Hello").await?;
```

Pure local helpers remain synchronous, including:

- `Value::map`
- `Value::get`
- `Value::as_str` / `as_i64` / `as_u64` / `as_bool`
- `Value::encode_cbor`
- `Value::decode_cbor`
- `Response::cbor`
- `Response::into_cbor`
- `Response::into_result`
- `Client::is_authenticated`
