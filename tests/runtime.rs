// Runs the committed objects against Synchronicity's production runtime.
// SSH lifecycle/SFTP checks adapted from upstream examples.rs (UPSTREAM.md).
mod harness;
use harness::{converse, exchange, peer, Harness};
use std::sync::Arc;
use synch_core::SockStatus;
use synch_sock::{DuplexStream, EffectivePolicy, Limits};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn object(name: &str) -> Vec<u8> {
    std::fs::read(
        std::path::Path::new(&std::env::var("SYKIT_ROOT").unwrap())
            .join("objects")
            .join(format!("{name}.o")),
    )
    .unwrap()
}
fn diagnostic_key_hex() -> String {
    synch_sock::policy::NOBODY
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

// Parse fixtures through Synchronicity's actual node-ID alphabet.
fn allowed_key() -> String {
    let key = "mbugc3ugc3ugc3ugc3ugc3ugc3ugc3ugc3ugc3ugc3ugc3ugc3uy";
    assert_eq!(
        *key.parse::<synch_core::OriginId>()
            .unwrap()
            .as_key()
            .unwrap(),
        peer(None).device_key
    );
    key.into()
}
fn alternate_key() -> String {
    "ee6486k16kn8jo96huhtyjs4yfn6acpr4nbusyy69bs4oh1hhx7o".into()
}
fn allowed_keys() -> String {
    format!("{}, {}", alternate_key(), allowed_key())
}

#[tokio::test]
async fn ssh_denies_before_handshake_even_with_spoofed_metadata() {
    let elf = object("ssh-shell");
    for key in [
        None,
        Some(String::new()),
        Some("a".repeat(63)),
        Some("g".repeat(64)),
        Some("a".repeat(65)),
        Some("0".repeat(64)),
        Some(alternate_key()),
        Some(format!("{},invalid", allowed_key())),
        Some(format!("{},", allowed_key())),
        Some(format!(",{}", allowed_key())),
        Some(format!("{},,{}", alternate_key(), allowed_key())),
        Some(format!("{}=", allowed_key())),
        Some(format!("{}{}", allowed_key(), " ".repeat(1024))),
    ] {
        let policy = EffectivePolicy {
            config: key
                .map(|k| vec![("allowed_node_key".into(), k)])
                .unwrap_or_default(),
            ..EffectivePolicy::default()
        };
        let (status, output) = exchange(
            &Harness::new(),
            &elf,
            b"SSH-2.0-test\r\n",
            policy,
            peer(None),
            vec![("allowed_node_key".into(), allowed_key())],
        )
        .await;
        assert_eq!(status, SockStatus::Ok(1));
        assert!(
            output.is_empty(),
            "denied nodes must not receive an SSH banner"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn echo_preserves_bytes_under_backpressure() {
    let payload: Vec<u8> = (0..96 * 1024).map(|i| (i % 251) as u8).collect();
    let harness = Harness::with_limits(Limits {
        ring_bytes: 4096,
        ..Limits::default()
    });
    let (status, out) = converse(&harness, &object("echo"), payload.clone(), 4096).await;
    assert_eq!(out, payload);
    assert_eq!(status, SockStatus::Ok(payload.len() as i64));
}

#[tokio::test]
async fn whoami_sends_identity_and_closes_without_client_eof() {
    use std::time::Duration;
    let harness = Harness::new();
    let (mut client, server) = tokio::io::duplex(32);
    let (reader, writer) = tokio::io::split(server);
    let invocation = harness.invocation(
        &object("whoami"),
        DuplexStream::new(reader, writer),
        EffectivePolicy::default(),
        peer(None),
        vec![("tag".into(), "\npeer-key: forged".into())],
    );
    let run = tokio::spawn(async move { harness.pool.run(invocation).await.unwrap() });
    let mut out = Vec::new();
    // Keep the client's write half open and send nothing. The server must
    // flush its complete reply and EOF even while a client could send input.
    tokio::time::timeout(Duration::from_secs(2), client.read_to_end(&mut out))
        .await
        .expect("whoami must close without waiting for client EOF")
        .unwrap();
    let outcome = tokio::time::timeout(Duration::from_secs(2), run)
        .await
        .expect("the server invocation must finish")
        .unwrap();
    assert_eq!(outcome.status, SockStatus::Ok(0));
    assert_eq!(
        String::from_utf8(out).unwrap(),
        format!(
            "peer-origin: {}\npeer-key: {}\npeer-kind: member\n",
            peer(None).origin,
            diagnostic_key_hex()
        )
    );
}

/// A stock SSH client for the shell example: the transport is already
/// authenticated by the harness, so the host key is accepted as presented.
struct ShellClient;

/// Waits for the shell's startup output to settle — the prompt is drawn and
/// nothing more arrives for half a second — before the test types anything.
///
/// A real user types at the prompt, and old interactive shells depend on it:
/// bash 3.2 (macOS's `/bin/bash`) configures its terminal with flush-style
/// `tcsetattr` during startup, discarding keystrokes that arrived early,
/// where modern bash deliberately preserves that typeahead.
async fn settle_at_prompt(channel: &mut russh::Channel<russh::client::Msg>, output: &mut Vec<u8>) {
    use std::time::Duration;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        match tokio::time::timeout(Duration::from_millis(500), channel.wait()).await {
            Ok(Some(russh::ChannelMsg::Data { data })) => output.extend_from_slice(&data),
            Ok(Some(russh::ChannelMsg::ExtendedData { data, .. })) => {
                output.extend_from_slice(&data)
            }
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(_) => {
                if !output.is_empty() {
                    break;
                }
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "the shell never drew its prompt"
                );
            }
        }
    }
}

impl russh::client::Handler for ShellClient {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// `ssh-shell.c` end to end: SSH `none` completes against the outer identity,
/// `pty-req` allocates a terminal without starting anything, `shell` starts
/// exactly the declared `/bin/bash`, the splice loop carries keystrokes and
/// output both ways, and the shell's own exit status arrives after its last
/// output rather than racing it away.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ssh_shell_serves_the_declared_bash_on_a_pty() {
    use std::time::Duration;

    let elf = object("ssh-shell");
    let harness = Harness::new();

    // The declaration is the whole approval surface: the exact executable and
    // argv, PTY permission, and nothing an SSH client could widen.
    let declaration = synch_sock::manifest::manifest_declaration(&elf).expect("the hook ran");
    assert_eq!(
        declaration.processes.len(),
        1,
        "one exact process capability is what the operator approves"
    );
    let bash = &declaration.processes[0];
    // The declared path is resolved at arm time, so a merged-/usr host shows
    // the operator `/usr/bin/bash` for a program that named `/bin/bash`.
    assert!(
        bash.executable.ends_with("/bash"),
        "the resolved shell is still bash: {}",
        bash.executable
    );
    assert_eq!(bash.argv, vec!["bash".to_string()]);
    assert_eq!(bash.flags & 0x01, 0x01, "PTY permission is declared");

    let policy = EffectivePolicy::granted(
        &declaration,
        vec![("allowed_node_key".into(), allowed_keys())],
        None,
        64,
    );
    let (client_stream, server_stream) = tokio::io::duplex(256 * 1024);
    let (server_reader, server_writer) = tokio::io::split(server_stream);
    let invocation = harness.invocation(
        &elf,
        DuplexStream::new(server_reader, server_writer),
        policy,
        peer(None),
        vec![],
    );
    let run = tokio::spawn(async move { harness.pool.run(invocation).await.unwrap() });

    let mut client = russh::client::connect_stream(
        Arc::new(russh::client::Config::default()),
        client_stream,
        ShellClient,
    )
    .await
    .expect("SSH handshake completed");
    assert!(
        client
            .authenticate_none("operator")
            .await
            .expect("none authentication got a response")
            .success(),
        "the outer identity is the authentication factor here"
    );

    let mut channel = client
        .channel_open_session()
        .await
        .expect("a session channel");
    channel
        .request_pty(true, "xterm", 80, 24, 0, 0, &[])
        .await
        .expect("the pty request was sent");
    assert!(
        matches!(
            tokio::time::timeout(Duration::from_secs(10), channel.wait())
                .await
                .expect("a pty-req answer"),
            Some(russh::ChannelMsg::Success)
        ),
        "allocating the terminal succeeds without starting a process"
    );
    channel
        .request_shell(true)
        .await
        .expect("the shell request was sent");
    assert!(
        matches!(
            tokio::time::timeout(Duration::from_secs(10), channel.wait())
                .await
                .expect("a shell answer"),
            Some(russh::ChannelMsg::Success)
        ),
        "the declared shell started"
    );

    // Type only once the prompt is drawn, as a person would.
    let mut output = Vec::new();
    settle_at_prompt(&mut channel, &mut output).await;

    // Typed at the terminal: bash expands the arithmetic, so seeing the
    // expansion in the output proves a real shell ran — the echoed input
    // still spells `$((6*7))`.
    channel
        .data(&b"echo interactive-$((6*7)); exit 3\n"[..])
        .await
        .expect("keystrokes reached the channel");

    // The server reports the shell's exit, EOF, and CHANNEL_CLOSE without
    // needing another client byte. A shell that dies by signal concludes too,
    // so the failure diagnostics can say who killed it rather than showing
    // silence.
    let mut exit_status = None;
    let mut exit_signal = None;
    let mut eof = false;
    let mut closed = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !(eof && closed && (exit_status.is_some() || exit_signal.is_some())) {
        let message = tokio::time::timeout_at(deadline, channel.wait())
            .await
            .expect("the shell session concluded");
        eprintln!("channel message: {message:?}");
        match message {
            Some(russh::ChannelMsg::Data { data }) => output.extend_from_slice(&data),
            Some(russh::ChannelMsg::ExtendedData { data, .. }) => output.extend_from_slice(&data),
            Some(russh::ChannelMsg::ExitStatus { exit_status: code }) => exit_status = Some(code),
            Some(russh::ChannelMsg::ExitSignal { signal_name, .. }) => {
                exit_signal = Some(format!("{signal_name:?}"))
            }
            Some(russh::ChannelMsg::Eof) => eof = true,
            Some(russh::ChannelMsg::Close) => closed = true,
            None => {
                closed = true;
                break;
            }
            Some(_) => {}
        }
    }
    let text = String::from_utf8_lossy(&output);
    assert!(
        text.contains("interactive-42"),
        "bash did not run the command.\noutput: {text:?}\nexit status: {exit_status:?}\nexit signal: {exit_signal:?}"
    );
    assert_eq!(
        exit_status,
        Some(3),
        "the shell's own exit status reached the client.\noutput: {text:?}\nexit signal: {exit_signal:?}"
    );
    assert!(eof && closed, "the server did not finish the channel");

    // A second login on the same connection: the finished session freed its
    // slot, so a fresh shell starts with a fresh lifecycle (§7.3).
    let mut second = client
        .channel_open_session()
        .await
        .expect("a second session channel");
    second
        .request_pty(true, "xterm", 80, 24, 0, 0, &[])
        .await
        .expect("the second pty request was sent");
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(10), second.wait())
            .await
            .expect("a second pty-req answer"),
        Some(russh::ChannelMsg::Success)
    ));
    second
        .request_shell(true)
        .await
        .expect("the second shell request was sent");
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(10), second.wait())
            .await
            .expect("a second shell answer"),
        Some(russh::ChannelMsg::Success)
    ));
    let mut second_output = Vec::new();
    settle_at_prompt(&mut second, &mut second_output).await;
    second
        .data(&b"exit 0\n"[..])
        .await
        .expect("keystrokes reached the second channel");
    let mut second_status = None;
    let mut second_closed = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while second_status.is_none() || !second_closed {
        match tokio::time::timeout_at(deadline, second.wait())
            .await
            .expect("the second shell concluded")
        {
            Some(russh::ChannelMsg::ExitStatus { exit_status }) => {
                second_status = Some(exit_status)
            }
            Some(russh::ChannelMsg::Close) => second_closed = true,
            None => {
                second_closed = true;
                break;
            }
            Some(_) => {}
        }
    }
    assert_eq!(
        second_status,
        Some(0),
        "the second session ran to completion"
    );
    assert!(second_closed, "the second channel was never closed");

    client
        .disconnect(russh::Disconnect::ByApplication, "logout", "en")
        .await
        .expect("a clean disconnect");
    drop(client);
    let outcome = tokio::time::timeout(Duration::from_secs(10), run)
        .await
        .expect("the invocation ended with the connection")
        .unwrap();
    assert_eq!(outcome.status, SockStatus::Ok(0));
}

/// The same shipped program is a writable SFTP server, not merely an SSH
/// transport that happens to recognize a subsystem name. Upload close commits
/// through the declared tree writer, and remove publishes a tombstone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ssh_shell_serves_declared_read_write_sftp() {
    use std::time::Duration;

    let elf = object("ssh-shell");
    let harness = Harness::with_tree(&[
        ("files/hello.txt", "hello over sftp"),
        ("secret.txt", "outside scope"),
    ]);
    let declaration =
        synch_sock::manifest::manifest_declaration(&elf).expect("the manifest parsed");
    assert_eq!(declaration.file_transfers.len(), 1);
    assert_eq!(declaration.file_transfers[0].access, 0x01 | 0x02 | 0x04);
    assert_eq!(declaration.file_transfers[0].scope, "files");
    assert_eq!(declaration.tree_writes.len(), 1);
    assert_eq!(declaration.tree_writes[0].prefix, "files");
    assert_eq!(declaration.tree_writes[0].modes, 0x01 | 0x02 | 0x04);

    let policy = EffectivePolicy::granted(
        &declaration,
        vec![("allowed_node_key".into(), allowed_keys())],
        None,
        64,
    );
    let (client_stream, server_stream) = tokio::io::duplex(256 * 1024);
    let (server_reader, server_writer) = tokio::io::split(server_stream);
    let mut caller = peer(None);
    caller.device_key = *alternate_key()
        .parse::<synch_core::OriginId>()
        .unwrap()
        .as_key()
        .unwrap();
    let invocation = harness.invocation(
        &elf,
        DuplexStream::new(server_reader, server_writer),
        policy,
        caller,
        vec![],
    );
    let run = tokio::spawn(async move { harness.pool.run(invocation).await.unwrap() });

    let mut client = russh::client::connect_stream(
        Arc::new(russh::client::Config::default()),
        client_stream,
        ShellClient,
    )
    .await
    .expect("SSH handshake completed");
    assert!(client
        .authenticate_none("operator")
        .await
        .unwrap()
        .success());
    // Recover the slot after abandonment both before and after PTY allocation.
    let mut channel = client.channel_open_session().await.unwrap();
    for with_pty in [false, true] {
        if with_pty {
            channel
                .request_pty(true, "xterm", 80, 24, 0, 0, &[])
                .await
                .unwrap();
            assert!(matches!(
                channel.wait().await,
                Some(russh::ChannelMsg::Success)
            ));
        }
        channel.close().await.unwrap();
        drop(channel);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        channel = loop {
            match client.channel_open_session().await {
                Ok(channel) => break channel,
                Err(_) if tokio::time::Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                Err(error) => panic!("abandoned channel retained the session slot: {error}"),
            }
        };
    }
    channel
        .request_subsystem(true, "sftp\0unexpected")
        .await
        .unwrap();
    assert!(
        matches!(
            tokio::time::timeout(Duration::from_secs(5), channel.wait())
                .await
                .unwrap(),
            Some(russh::ChannelMsg::Failure)
        ),
        "only the exact subsystem name may be accepted"
    );
    channel.exec(true, "printf unwanted").await.unwrap();
    assert!(matches!(
        channel.wait().await,
        Some(russh::ChannelMsg::Failure)
    ));
    channel
        .set_env(true, "SYKIT_TEST", "untrusted")
        .await
        .unwrap();
    assert!(matches!(
        channel.wait().await,
        Some(russh::ChannelMsg::Failure)
    ));
    assert!(client
        .channel_open_direct_tcpip("127.0.0.1", 9, "127.0.0.1", 12345)
        .await
        .is_err());
    assert!(
        client.channel_open_session().await.is_err(),
        "only one active session is allowed"
    );
    channel
        .request_subsystem(true, "sftp")
        .await
        .expect("the SFTP subsystem request was sent");
    let sftp = russh_sftp::client::SftpSession::new(channel.into_stream())
        .await
        .expect("the SFTP version exchange completed");

    for path in ["../secret.txt", "/../secret.txt", "sub/../../secret.txt"] {
        assert!(
            sftp.read(path).await.is_err(),
            "escaped the read scope: {path}"
        );
        assert!(
            sftp.create(path).await.is_err(),
            "escaped the write scope: {path}"
        );
        assert!(
            sftp.remove_file(path).await.is_err(),
            "escaped the delete scope: {path}"
        );
    }
    assert!(harness.tree.written.lock().unwrap().is_empty());
    assert!(harness.tree.deleted.lock().unwrap().is_empty());
    assert_eq!(sftp.read("hello.txt").await.unwrap(), b"hello over sftp");
    let mut upload = sftp.create("upload.txt").await.expect("a writable file");
    upload
        .write_all(b"written through the shipped server")
        .await
        .expect("the upload bytes were accepted");
    upload.close().await.expect("close committed the upload");
    assert_eq!(
        harness.tree.written.lock().unwrap().get("files/upload.txt"),
        Some(&b"written through the shipped server".to_vec())
    );

    sftp.remove_file("upload.txt")
        .await
        .expect("remove published a tombstone");
    assert!(harness
        .tree
        .deleted
        .lock()
        .unwrap()
        .contains(&"files/upload.txt".to_string()));
    sftp.close().await.expect("the SFTP session closed");

    client
        .disconnect(russh::Disconnect::ByApplication, "done", "en")
        .await
        .unwrap();
    drop(client);
    let outcome = tokio::time::timeout(Duration::from_secs(10), run)
        .await
        .expect("the invocation ended with the connection")
        .unwrap();
    assert_eq!(outcome.status, SockStatus::Ok(0));
}
