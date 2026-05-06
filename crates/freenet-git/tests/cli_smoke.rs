//! End-to-end CLI smoke test using the actual `freenet-git` binary
//! against a temp identity bundle path. Exercises the offline commands.
//!
//! Network commands (`create --publish-to`) live in the e2e harness.

use std::process::{Command, Stdio};

fn binary_path() -> std::path::PathBuf {
    let mut p = std::env::current_exe().expect("current_exe");
    // .../target/debug/deps/cli_smoke-XXXX -> .../target/debug/deps
    p.pop(); // pop test binary name
    if p.ends_with("deps") {
        p.pop();
    }
    p.join("freenet-git")
}

fn cli(bundle_path: &std::path::Path, passphrase: &str) -> Command {
    let mut cmd = Command::new(binary_path());
    cmd.env("FREENET_GIT_IDENTITY", bundle_path);
    // Tests run without a TTY, so the prompt env var path is required.
    cmd.env("FREENET_GIT_PASSPHRASE", passphrase);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd
}

/// Like `cli` but with `FREENET_GIT_PASSPHRASE` explicitly *unset*.
/// Use this to exercise the unencrypted-bundle code paths the way a CI
/// workflow that hasn't exported any passphrase would actually hit them.
fn cli_no_env(bundle_path: &std::path::Path) -> Command {
    let mut cmd = Command::new(binary_path());
    cmd.env("FREENET_GIT_IDENTITY", bundle_path);
    cmd.env_remove("FREENET_GIT_PASSPHRASE");
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd
}

fn run(mut cmd: Command) -> std::process::Output {
    cmd.spawn()
        .expect("spawn")
        .wait_with_output()
        .expect("wait")
}

#[test]
fn init_identity_creates_bundle_and_whoami_reads_it() {
    let dir = tempfile::tempdir().unwrap();
    let bundle = dir.path().join("id.bundle");

    let mut init = cli(&bundle, "correct horse");
    init.args([
        "init-identity",
        "--name",
        "Tester",
        "--email",
        "tester@example.com",
    ]);
    let out = run(init);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "init-identity failed; stderr: {stderr}"
    );
    assert!(
        stdout.contains("Generated ed25519 keypair"),
        "got stdout: {stdout}"
    );
    assert!(stdout.contains("freenet:id:"), "got stdout: {stdout}");
    assert!(bundle.exists(), "bundle file should have been written");

    let mut whoami = cli(&bundle, "correct horse");
    whoami.arg("whoami");
    let out = run(whoami);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "whoami failed; stderr: {stderr}");
    assert!(
        stdout.contains("Tester <tester@example.com>"),
        "got stdout: {stdout}"
    );
    assert!(stdout.contains("freenet:id:"), "got stdout: {stdout}");
}

#[test]
fn whoami_with_wrong_passphrase_fails() {
    let dir = tempfile::tempdir().unwrap();
    let bundle = dir.path().join("id.bundle");

    let mut init = cli(&bundle, "right-passphrase");
    init.args(["init-identity", "--name", "X", "--email", "x@e.com"]);
    assert!(run(init).status.success());

    let mut whoami = cli(&bundle, "wrong-passphrase");
    whoami.arg("whoami");
    let out = run(whoami);
    assert!(!out.status.success(), "wrong passphrase should fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("decrypt")
            || stderr.contains("Decryption")
            || stderr.contains("decryption"),
        "expected decrypt error, got: {stderr}"
    );
}

#[test]
fn init_identity_rejects_overwriting_existing_bundle() {
    let dir = tempfile::tempdir().unwrap();
    let bundle = dir.path().join("id.bundle");
    std::fs::write(&bundle, b"placeholder").unwrap();

    let mut init = cli(&bundle, "x");
    init.args(["init-identity", "--name", "X", "--email", "x@e.com"]);
    let out = run(init);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("refusing to overwrite"),
        "expected refusal, got: {stderr}"
    );
}

#[test]
fn no_passphrase_init_and_whoami_with_env_unset() {
    // The headline use case: a CI workflow that has not exported any
    // FREENET_GIT_PASSPHRASE creates an unencrypted bundle and inspects it.
    // Both commands must succeed without a TTY and without prompting.
    let dir = tempfile::tempdir().unwrap();
    let bundle = dir.path().join("id.bundle");

    let mut init = cli_no_env(&bundle);
    init.args([
        "init-identity",
        "--no-passphrase",
        "--name",
        "CI",
        "--email",
        "ci@example.com",
    ]);
    let out = run(init);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "init-identity --no-passphrase failed; stderr: {stderr}"
    );
    assert!(
        stdout.contains("unencrypted at rest"),
        "expected unencrypted notice; got: {stdout}"
    );
    assert!(bundle.exists(), "bundle should have been written");

    let mut whoami = cli_no_env(&bundle);
    whoami.arg("whoami");
    let out = run(whoami);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "whoami without env var failed; stderr: {stderr}"
    );
    assert!(
        stdout.contains("CI <ci@example.com>"),
        "got stdout: {stdout}"
    );
    assert!(
        stdout.contains("Encryption: none"),
        "whoami should report unencrypted status; got: {stdout}"
    );
    // The opener prints a warning when a silent-empty fallback opens a
    // bundle and the user did NOT opt in via FREENET_GIT_PASSPHRASE="".
    // Here the env var is unset, so the warning fires.
    assert!(
        stderr.contains("opened unencrypted identity bundle"),
        "expected silent-fallback warning; got stderr: {stderr}"
    );
}

#[test]
fn no_passphrase_create_round_trip_preserves_registry() {
    // The `register_in_bundle` refactor reuses the opener passphrase
    // instead of re-prompting. This test exercises that for the
    // unencrypted path: after `create`, the bundle must still be
    // openable and must contain the new registry entry.
    let dir = tempfile::tempdir().unwrap();
    let bundle = dir.path().join("id.bundle");
    let fake_wasm = dir.path().join("repo.wasm");
    std::fs::write(&fake_wasm, b"fake-wasm-bytes").unwrap();

    let mut init = cli_no_env(&bundle);
    init.args([
        "init-identity",
        "--no-passphrase",
        "--name",
        "Owner",
        "--email",
        "o@e.com",
    ]);
    assert!(run(init).status.success(), "init failed");

    let mut create = cli_no_env(&bundle);
    create.args([
        "create",
        "--name",
        "demo",
        "--description",
        "round-trip test",
        "--no-publish",
        "--repo-wasm",
    ]);
    create.arg(&fake_wasm);
    let out = run(create);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "create failed; stderr: {stderr}");
    assert!(stdout.contains("Registered repo"), "got stdout: {stdout}");

    // Re-open: the bundle should still be unencrypted AND contain the
    // new repo entry.
    let mut whoami = cli_no_env(&bundle);
    whoami.arg("whoami");
    let out = run(whoami);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "post-create whoami failed: {stderr}");
    assert!(
        stdout.contains("Encryption: none"),
        "bundle must remain unencrypted after create; got: {stdout}"
    );
    assert!(
        stdout.contains("freenet:") && stdout.contains("/demo"),
        "expected the new repo URL in the registry listing; got: {stdout}"
    );
}

#[test]
fn empty_env_passphrase_at_init_directs_to_no_passphrase_flag() {
    // A user with FREENET_GIT_PASSPHRASE="" exported in their shell who
    // forgets the --no-passphrase flag should get a helpful error,
    // not a silent encrypted-with-empty-passphrase bundle. This pins
    // the explicit opt-in design: --no-passphrase is the only way to
    // create an unencrypted bundle via the CLI.
    let dir = tempfile::tempdir().unwrap();
    let bundle = dir.path().join("id.bundle");

    let mut init = cli(&bundle, "");
    init.args(["init-identity", "--name", "X", "--email", "x@e.com"]);
    let out = run(init);
    assert!(
        !out.status.success(),
        "empty env without --no-passphrase should fail"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--no-passphrase"),
        "error should direct to --no-passphrase; got: {stderr}"
    );
    assert!(!bundle.exists(), "no bundle should be written on error");
}

#[test]
fn stale_env_passphrase_with_unencrypted_bundle_falls_back_to_empty() {
    // Codex P2 / Skeptical H3: a developer with a stale
    // FREENET_GIT_PASSPHRASE exported (e.g. from yesterday's encrypted
    // bundle) should still be able to read an unencrypted bundle. The
    // env-var-takes-precedence branch must fall through to the empty
    // passphrase rather than bailing on decrypt.
    let dir = tempfile::tempdir().unwrap();
    let bundle = dir.path().join("id.bundle");

    // Create unencrypted.
    let mut init = cli_no_env(&bundle);
    init.args([
        "init-identity",
        "--no-passphrase",
        "--name",
        "X",
        "--email",
        "x@e.com",
    ]);
    assert!(run(init).status.success());

    // Now read with a stale env var set to a real (wrong) passphrase.
    let mut whoami = cli(&bundle, "stale-passphrase-from-yesterday");
    whoami.arg("whoami");
    let out = run(whoami);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "whoami should fall back to empty for unencrypted bundle; stderr: {stderr}"
    );
    assert!(
        stdout.contains("Encryption: none"),
        "bundle is unencrypted; got: {stdout}"
    );
}

#[test]
fn create_repo_prints_url_and_writes_temp_artifacts() {
    let dir = tempfile::tempdir().unwrap();
    let bundle = dir.path().join("id.bundle");

    // 1. init identity.
    let mut init = cli(&bundle, "pw");
    init.args(["init-identity", "--name", "Owner", "--email", "o@e.com"]);
    assert!(run(init).status.success());

    // 2. write a tiny stand-in WASM file. The CLI does not execute it, it
    //    just hashes the bytes to derive the contract id, so any bytes
    //    work for this test.
    let fake_wasm = dir.path().join("repo.wasm");
    std::fs::write(&fake_wasm, b"fake-wasm-bytes-for-id-derivation").unwrap();

    // 3. run `create` without --publish-to. With no registered repos and
    //    a passphrase that lets us re-write the bundle, the command
    //    succeeds and prints a freenet:... URL.
    let mut create = cli(&bundle, "pw");
    create.args([
        "create",
        "--name",
        "demo",
        "--description",
        "a demo repo",
        "--no-publish",
        "--repo-wasm",
    ]);
    create.arg(&fake_wasm);
    let out = run(create);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "create failed; stderr: {stderr}");
    assert!(stdout.contains("URL:"), "got stdout: {stdout}");
    assert!(stdout.contains("freenet:"), "got stdout: {stdout}");
    assert!(
        stdout.contains("Registered repo"),
        "should record in bundle: {stdout}"
    );
}
