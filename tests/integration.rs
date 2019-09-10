use assert_cmd::prelude::*;
use byteorder::{LittleEndian, WriteBytesExt};
use gpgme::{Context, Data};
use predicates::prelude::*;
use serde_json::json;
use std::fs::File;
use std::process::Command;

const INPUT_FILE: &str = "./tests/message.txt";

fn to_native_message(json: &serde_json::value::Value) -> Vec<u8> {
	let result = json.to_string();
	let mut result_bytes = Vec::new();
	result_bytes
		.write_i32::<LittleEndian>(result.as_bytes().len() as i32)
		.unwrap();
	result_bytes.extend_from_slice(result.as_bytes());
	result_bytes
}

fn compare_native_message(lhs: &[u8], rhs_json: &serde_json::value::Value) -> bool {
	if lhs.is_empty() {
		return false;
	}
	let lhs_json: serde_json::value::Value = serde_json::from_slice(&lhs[4..]).expect("lhs json");
	let l = lhs_json.as_object().expect("lhs object");
	let r = rhs_json.as_object().expect("rhs object");
	if l != r {
		eprintln!("\nexpected:\n{:?}\nreceived:\n{:?}", r, l);
	}
	l == r
}

fn create_result(
	integrity: &str,
	signatures: &[&str],
	integrity_status: &str,
	signatures_status: &str,
) -> serde_json::value::Value {
	json!({
		"integrity": {
			integrity_status: integrity,
		},
		"signatures": {
			signatures_status: signatures,
		}
	})
}

fn create_result_sig_str(
	integrity: &str,
	signatures: &str,
	integrity_status: &str,
	signatures_status: &str,
) -> serde_json::value::Value {
	json!({
		"integrity": {
			integrity_status: integrity,
		},
		"signatures": {
			signatures_status: signatures,
		}
	})
}

fn create_result_ok(integrity: &str, signatures: &[&str]) -> serde_json::value::Value {
	create_result(integrity, signatures, "Ok", "Ok")
}

fn create_result_integrity_err(integrity: &str, signatures: &[&str]) -> serde_json::value::Value {
	create_result(integrity, signatures, "Err", "Ok")
}

fn create_result_auth_err(integrity: &str, signatures: &str) -> serde_json::value::Value {
	create_result_sig_str(integrity, signatures, "Ok", "Err")
}

fn import_test_key() {
	let mut ctx = Context::from_protocol(gpgme::Protocol::OpenPgp).expect("creating context");
	let input = File::open("./tests/public.gpg").expect("opening public key");
	let mut data = Data::from_seekable_stream(input).expect("reading public key");
	ctx.import(&mut data).expect("importing test key");
}

fn remove_test_key() {
	let mut ctx = Context::from_protocol(gpgme::Protocol::OpenPgp).expect("creating context");
	let key = ctx
		.get_key("46E28286D4420F05C73C0C45159D64C7B6DBC78D")
		.expect("getting test key");
	ctx.delete_key(&key).expect("deleting test key");
}

#[test]
fn version_request() {
	let input: serde_json::value::Value = json!({
		"version-request": true,
	});
	let input_bytes = to_native_message(&input);
	let output = json!({
		"version": env!("CARGO_PKG_VERSION").to_string(),
	});
	let predicate_fn = predicate::function(|lhs: &[u8]| compare_native_message(lhs, &output));
	let mut cmd = Command::cargo_bin("vd-verifier").unwrap();
	cmd.with_stdin().buffer(input_bytes).assert().stdout(predicate_fn);
}

#[test]
fn integrity_ok() {
	let input: serde_json::value::Value = json!({
		"digest-file": "./tests/message.txt.sha256",
		"input-file": INPUT_FILE,
		"original-filename": INPUT_FILE,
	});
	let input_bytes = to_native_message(&input);
	let output = create_result_ok("PASS", &[]);
	let predicate_fn = predicate::function(|lhs: &[u8]| compare_native_message(lhs, &output));
	let mut cmd = Command::cargo_bin("vd-verifier").unwrap();
	cmd.with_stdin().buffer(input_bytes).assert().stdout(predicate_fn);
}

#[test]
fn integrity_fail() {
	let input: serde_json::value::Value = json!({
		"digest-file": "./tests/message.txt.fail.sha256",
		"input-file": INPUT_FILE,
		"original-filename": INPUT_FILE,
	});
	let input_bytes = to_native_message(&input);
	let output = create_result_ok("FAIL", &[]);
	let predicate_fn = predicate::function(|lhs: &[u8]| compare_native_message(lhs, &output));
	let mut cmd = Command::cargo_bin("vd-verifier").unwrap();
	cmd.with_stdin().buffer(input_bytes).assert().stdout(predicate_fn);
}

#[test]
fn integrity_not_present() {
	let input: serde_json::value::Value = json!({
		"digest-file": "./tests/message.txt.notpresent.sha256",
		"input-file": INPUT_FILE,
		"original-filename": INPUT_FILE,
	});
	let input_bytes = to_native_message(&input);
	let output = create_result_integrity_err(
		"Digest file is not well-formed or does not contain corresponding digest",
		&[],
	);
	let predicate_fn = predicate::function(|lhs: &[u8]| compare_native_message(lhs, &output));
	let mut cmd = Command::cargo_bin("vd-verifier").unwrap();
	cmd.with_stdin().buffer(input_bytes).assert().stdout(predicate_fn);
}

#[test]
fn integrity_fallback_if_single_hexstr_present() {
	let input: serde_json::value::Value = json!({
		"digest-file": "./tests/message.txt.oneline.fallback.sha256",
		"input-file": INPUT_FILE,
		"original-filename": INPUT_FILE,
	});
	let input_bytes = to_native_message(&input);
	let output = create_result_ok("PASS", &[]);
	let predicate_fn = predicate::function(|lhs: &[u8]| compare_native_message(lhs, &output));
	let mut cmd = Command::cargo_bin("vd-verifier").unwrap();
	cmd.with_stdin().buffer(input_bytes).assert().stdout(predicate_fn);
}

#[test]
fn signature_valid() {
	import_test_key();
	let input: serde_json::value::Value = json!({
		"signature-file": "./tests/message.txt.asc",
		"input-file": INPUT_FILE,
		"signed-data": "data",
	});
	let input_bytes = to_native_message(&input);
	let output = create_result_ok("UNTESTED", &["PASS"]);
	let predicate_fn = predicate::function(|lhs: &[u8]| compare_native_message(lhs, &output));
	let mut cmd = Command::cargo_bin("vd-verifier").unwrap();
	cmd.with_stdin().buffer(input_bytes).assert().stdout(predicate_fn);
	remove_test_key();
}

#[test]
fn signature_bad_signature() {
	import_test_key();
	let input: serde_json::value::Value = json!({
		"signature-file": "./tests/message.txt.asc",
		"input-file": "./tests/forged.txt",
		"signed-data": "data",
	});
	let input_bytes = to_native_message(&input);
	let output = create_result_ok("UNTESTED", &["Bad signature"]);
	let predicate_fn = predicate::function(|lhs: &[u8]| compare_native_message(lhs, &output));
	let mut cmd = Command::cargo_bin("vd-verifier").unwrap();
	cmd.with_stdin().buffer(input_bytes).assert().stdout(predicate_fn);
	remove_test_key();
}

#[test]
fn signature_missing_signature() {
	import_test_key();
	let input: serde_json::value::Value = json!({
		"signature-file": "./tests/nonexistent.txt.asc",
		"input-file": INPUT_FILE,
		"signed-data": "data",
	});
	let input_bytes = to_native_message(&input);
	let output = create_result_auth_err(
		"UNTESTED",
		"No such file or directory (os error 2) while opening signature file",
	);
	let predicate_fn = predicate::function(|lhs: &[u8]| compare_native_message(lhs, &output));
	let mut cmd = Command::cargo_bin("vd-verifier").unwrap();
	cmd.with_stdin().buffer(input_bytes).assert().stdout(predicate_fn);
	remove_test_key();
}

#[test]
fn signature_missing_key_in_store() {
	// not importing test key
	let input: serde_json::value::Value = json!({
		"signature-file": "./tests/message.txt.asc",
		"input-file": INPUT_FILE,
		"signed-data": "data",
	});
	let input_bytes = to_native_message(&input);
	let output = create_result_ok("UNTESTED", &["No public key"]);
	let predicate_fn = predicate::function(|lhs: &[u8]| compare_native_message(lhs, &output));
	let mut cmd = Command::cargo_bin("vd-verifier").unwrap();
	cmd.with_stdin().buffer(input_bytes).assert().stdout(predicate_fn);
}

#[test]
fn signed_single_digest_ok() {
	import_test_key();
	let input: serde_json::value::Value = json!({
		"signature-file": "./tests/message.txt.sha256.asc",
		"input-file": INPUT_FILE,
		"digest-file": "./tests/message.txt.sha256",
		"signed-data": "digest",
	});
	let input_bytes = to_native_message(&input);
	let output = create_result_ok("PASS", &["PASS"]);
	let predicate_fn = predicate::function(|lhs: &[u8]| compare_native_message(lhs, &output));
	let mut cmd = Command::cargo_bin("vd-verifier").unwrap();
	cmd.with_stdin().buffer(input_bytes).assert().stdout(predicate_fn);
	remove_test_key();
}

#[test]
fn signed_single_digest_bad_digest() {
	import_test_key();
	let input: serde_json::value::Value = json!({
		"signature-file": "./tests/message.txt.fail.sha256.asc",
		"input-file": INPUT_FILE,
		"digest-file": "./tests/message.txt.fail.sha256",
		"signed-data": "digest",
	});
	let input_bytes = to_native_message(&input);
	let output = create_result_ok("FAIL", &[]);
	let predicate_fn = predicate::function(|lhs: &[u8]| compare_native_message(lhs, &output));
	let mut cmd = Command::cargo_bin("vd-verifier").unwrap();
	cmd.with_stdin().buffer(input_bytes).assert().stdout(predicate_fn);
	remove_test_key();
}

#[test]
fn signed_multiple_digests_file() {
	import_test_key();
	let input: serde_json::value::Value = json!({
		"signature-file": "./tests/sha256sums.gpg",
		"input-file": INPUT_FILE,
		"digest-file": "./tests/sha256sums",
		"signed-data": "digest",
	});
	let input_bytes = to_native_message(&input);
	let output = create_result_ok("PASS", &["PASS"]);
	let predicate_fn = predicate::function(|lhs: &[u8]| compare_native_message(lhs, &output));
	let mut cmd = Command::cargo_bin("vd-verifier").unwrap();
	cmd.with_stdin().buffer(input_bytes).assert().stdout(predicate_fn);
	remove_test_key();
}

