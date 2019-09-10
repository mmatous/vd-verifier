#[macro_use]
extern crate failure;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use failure::{Error, ResultExt};
use gpgme::{Context, Protocol, VerificationResult};
use hex::FromHex;
use ring::digest;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::{fs, io};

mod vdv;
use crate::vdv::*;

fn infer_digest_kind(digest: &[u8]) -> Result<&'static digest::Algorithm, VdError> {
	let digest_length = digest.len();
	match digest_length {
		digest::SHA1_OUTPUT_LEN => Ok(&digest::SHA1_FOR_LEGACY_USE_ONLY),
		digest::SHA256_OUTPUT_LEN => Ok(&digest::SHA256),
		digest::SHA512_OUTPUT_LEN => Ok(&digest::SHA512),
		_ => Err(VdError::InvalidDigestLength { digest_length }),
	}
}

fn digest_input<R: std::io::Read>(input: &mut R, d: &'static digest::Algorithm) -> Result<Vec<u8>, Error> {
	let mut ctx = digest::Context::new(d);
	let mut buf = [0_u8; 8 * 1024];
	while let Ok(read_len) = input.read(&mut buf) {
		if read_len == 0 {
			break;
		}
		ctx.update(&buf[..read_len]);
	}
	Ok(ctx.finish().as_ref().to_vec())
}

fn respond_to_extension<W: std::io::Write>(response: &str, writer: &mut W) -> Result<(), Error> {
	writer.write_i32::<LittleEndian>(i32::try_from(response.as_bytes().len())?)?;
	writer.write_all(response.as_bytes())?;
	Ok(())
}

fn read_message<R: std::io::Read>(reader: &mut R) -> Result<String, Error> {
	let message_length = reader.read_i32::<LittleEndian>()?;
	let mut buffer = vec![0_u8; usize::try_from(message_length).with_context(ctx!("parsing input"))?];
	reader
		.read_exact(buffer.as_mut_slice())
		.with_context(ctx!("reading message from extension"))?;
	Ok(String::from_utf8(buffer)?)
}

fn verify_digest(message: &VdMessage) -> Result<IntegritySummary, Error> {
	let provided_digest = message.get_digest()?;
	match provided_digest {
		Some(provided_digest) => {
			let digest_kind = infer_digest_kind(&provided_digest)?;
			let mut input_file =
				fs::File::open(&message.input_file).with_context(ctx!("opening input file"))?;
			let calculated_digest = digest_input(&mut input_file, digest_kind)?;
			if calculated_digest == provided_digest {
				Ok(IntegritySummary::Pass)
			} else {
				Ok(IntegritySummary::Fail)
			}
		}
		None => Err(VdError::MissingContent {
			file_type: s!("Digest file"),
			missing_data: s!("corresponding digest"),
		})?,
	}
}

fn interpret_verify_result(result: &VerificationResult) -> Vec<String> {
	eprintln!("{:?}", result);
	let mut res = Vec::new();
	for signature in result.signatures() {
		let status = match signature.status() {
			Ok(()) => s!("PASS"),
			Err(e) => e.description().to_string(),
		};
		res.push(status);
	}
	res
}

fn verify_signatures(input_file: &Path, signature_file: &Path) -> Result<Vec<String>, Error> {
	let mut ctx = Context::from_protocol(Protocol::OpenPgp)?;
	let signature = fs::File::open(signature_file).with_context(ctx!("opening signature file"))?;
	let signed = fs::File::open(&input_file).with_context(ctx!("opening input file for signature"))?;
	let result = ctx.verify_detached(signature, signed)?;
	Ok(interpret_verify_result(&result))
}

fn find_only_hex_string(text: &str) -> Option<Vec<u8>> {
	let re = regex::Regex::new(r"\b[[:xdigit:]]{40, 128}\b").expect("regex should be valid");
	let captures: Vec<_> = re.captures_iter(text).collect();
	if captures.len() == 1 {
		let c = &captures[0];
		return hex::decode(&c[0]).ok();
	}
	None
}

fn respond<S: Serialize>(result: &S) -> Result<(), Error> {
	let response = serde_json::to_string(&result)?;
	eprintln!("responding {}", serde_json::to_string_pretty(&result).unwrap());
	respond_to_extension(&response, &mut io::stdout())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "kebab-case")]
struct VdMessage {
	/// File name as supplied by the server
	original_filename: Option<PathBuf>,

	/// Absolute path to downloaded file
	input_file: PathBuf,

	/// File containing digest
	digest_file: Option<PathBuf>,

	/// Hex-encoded digest of input-file supplied directly
	digest_direct: Option<String>,

	/// File containing signed digest of input-file
	/// Digest-related and version fields are ignored if specified
	signature_file: Option<PathBuf>,

	/// Specify whether digest_file or 'input_file' should be used as a message
	/// for signature verification
	signed_data: Option<SignedDataKind>,
}

impl VdMessage {
	pub fn get_digest(&self) -> Result<Option<Vec<u8>>, Error> {
		if let Some(digest) = &self.digest_direct {
			let digest = Vec::from_hex(&digest).with_context(ctx!("parsing provided digest"))?;
			return Ok(Some(digest));
		}
		let path = self
			.digest_file
			.as_ref()
			.ok_or_else(|| VdError::MissingArgument {
				argument_name: s!("digest file path"),
			})?;
		let mut f = fs::File::open(&path).with_context(ctx!("opening digest file"))?;
		self.search_digest_file(&mut f)
	}

	fn search_digest_file<R: std::io::Read>(&self, file: &mut R) -> Result<Option<Vec<u8>>, Error> {
		let mut contents = String::new();
		file.read_to_string(&mut contents)
			.with_context(ctx!("reading contents of digest file"))?;
		let orig_filename = self.get_original_filename()?;
		for line in contents.lines() {
			let result = self.search_line(line, orig_filename)?;
			if result.is_some() {
				return Ok(result);
			};
		}
		if let Some(digest) = find_only_hex_string(&contents) {
			return Ok(Some(digest));
		}
		Ok(None)
	}

	fn search_line(&self, line: &str, orig_filename: &OsStr) -> Result<Option<Vec<u8>>, Error> {
		let tokens: Vec<&str> = line.split_whitespace().collect();
		if tokens.len() < 2 {
			return Ok(None);
		}
		let digest = tokens[0];
		let filename = tokens[1].trim_matches('*'); // * is possible filename prefix in *sums files
		if let Some(read_filename) = p!(filename).file_name() {
			if read_filename == orig_filename {
				let decoded = hex::decode(digest)?;
				return Ok(Some(decoded));
			}
		}
		Ok(None)
	}

	fn get_original_filename(&self) -> Result<&OsStr, Error> {
		if self.original_filename.is_some() {
			return Ok(OsStr::new(self.original_filename.as_ref().expect("fname exists")));
		}
		Ok(self.input_file.file_name().ok_or(VdError::MissingContent {
			file_type: s!("Input filename"),
			missing_data: s!("actual filename"),
		})?)
	}

	fn get_signature_file(&self) -> Result<&PathBuf, VdError> {
		self.signature_file
			.as_ref()
			.ok_or_else(|| VdError::MissingArgument {
				argument_name: s!("signature file path"),
			})
	}

	fn get_digest_file(&self) -> Result<&PathBuf, VdError> {
		self.digest_file.as_ref().ok_or_else(|| VdError::MissingArgument {
			argument_name: s!("digest file path"),
		})
	}
}

fn main() -> Result<(), Error> {
	let message = read_message(&mut io::stdin())?;
	let version_request: Result<VersionRequest, serde_json::error::Error> = serde_json::from_str(&message);
	if version_request.is_ok() {
		let response = ResponseVersion::default();
		return respond(&response);
	}
	let message: VdMessage = serde_json::from_str(&message)?;
	let mut response = Response::default();
	match message.signed_data {
		Some(SignedDataKind::Data) => {
			response.signatures = verify_signatures(&message.input_file, &message.get_signature_file()?)
				.map_err(|e| e.to_string());
		}
		Some(SignedDataKind::Digest) => {
			response.integrity = verify_digest(&message).map_err(|e| e.to_string());
			if response.integrity == Ok(IntegritySummary::Pass) {
				response.signatures =
					verify_signatures(&message.get_digest_file()?, &message.get_signature_file()?)
						.map_err(|e| e.to_string());
			}
		}
		None => {
			response.integrity = verify_digest(&message).map_err(|e| e.to_string());
		}
	}
	respond(&response)
}

#[cfg(test)]
mod test {
	use super::*;
	use serde_json::json;

	#[test]
	fn get_digest_returns_digest_if_valid_hexstr() {
		let obj: serde_json::value::Value = json!({
			"input-file": "/path/to/renamed spaced.f",
			"digest-direct": "DEADBEEF"
		});
		let p: VdMessage = serde_json::from_str(&obj.to_string()).unwrap();

		assert_eq!(p.get_digest().unwrap().unwrap(), vec![0xDE, 0xAD, 0xBE, 0xEF]);
	}

	#[test]
	fn get_digest_rejects_digest_if_invalid_hexstr() {
		let obj: serde_json::value::Value = json!({
			"input-file": "/path/to/renamed spaced.f",
			"digest-direct": "DEADBEET"
		});
		let p: VdMessage = serde_json::from_str(&obj.to_string()).unwrap();

		assert_eq!(
			p.get_digest().unwrap_err().to_string(),
			"Invalid character 'T' at position 7 while parsing provided digest"
		);
	}

	#[test]
	fn get_digest_returns_error_if_message_has_no_digest_field() {
		let obj: serde_json::value::Value = json!({
			"input-file": "/path/to/renamed spaced.f",
		});
		let p: VdMessage = serde_json::from_str(&obj.to_string()).unwrap();

		assert_eq!(
			p.get_digest().unwrap_err().to_string(),
			"Missing required argument: digest file path"
		);
	}

	#[test]
	fn search_file_returns_digest_if_passed_correct_digest_file_and_original_filename() {
		let obj: serde_json::value::Value = json!({
			"input-file": "/path/to/renamed spaced.f",
			"original-filename": "file",
		});
		let p: VdMessage = serde_json::from_str(&obj.to_string()).unwrap();
		let mut file: &[u8] = b"DEADBEEF *./file";

		assert_eq!(
			p.search_digest_file(&mut file).unwrap().unwrap(),
			vec![0xDE, 0xAD, 0xBE, 0xEF]
		);
	}

	#[test]
	fn search_digest_file_returns_none_if_digest_file_does_not_contain_digests() {
		let obj: serde_json::value::Value = json!({
			"input-file": "/path/to/renamed spaced.f",
			"original-filename": "orig_name",
			"digest-file": "/path/to/digest"
		});
		let p: VdMessage = serde_json::from_str(&obj.to_string()).unwrap();
		let mut file: &[u8] = b"not_hexdata *./file";

		assert_eq!(p.search_digest_file(&mut file).unwrap(), None);
	}

	#[test]
	fn find_only_hex_string_returns_hex_string_if_only_one_acceptable() {
		let text = "sha256 78a2284b43f6eae40f6f495eedb727eca845c4a3bfcd9d8c122ab3ac78ecfb71";

		let hexdata = find_only_hex_string(text);
		assert!(hexdata.is_some());
		assert_eq!(
			hexdata.unwrap(),
			Vec::from_hex("78a2284b43f6eae40f6f495eedb727eca845c4a3bfcd9d8c122ab3ac78ecfb71").unwrap()
		);
	}

	#[test]
	fn find_first_hex_string_returns_none_if_no_digest_present() {
		let text = "md5wannabe 78a2284b43f6eae40f6f495e"; // too short

		let hexdata = find_only_hex_string(text);
		assert!(hexdata.is_none());
	}

	#[test]
	fn digest_input_can_calculate_sha512() {
		let mut i: &[u8] = b"content to sha512\n";
		assert_eq!(
			digest_input(&mut i, &digest::SHA512).unwrap(),
			Vec::from_hex(
				"d43cb55cf99c1d726c9cf3cd4933171010db15afddff2f9cf612f3af2904b624dcb2ce\
				 7c3531b3193069d6bae487ed152b9d389b24b973d4f7460a95ed14e8e7"
			)
			.unwrap()
		);
	}

	#[test]
	fn search_line_accepts_shasums_format() {
		let obj: serde_json::value::Value = json!({
			"input-file": "/path/to/renamed spaced.f",
		});
		let p: VdMessage = serde_json::from_str(&obj.to_string()).unwrap();

		assert_eq!(
			p.search_line("DEADBEEE *processed.file", OsStr::new("processed.file"))
				.unwrap()
				.unwrap(),
			vec![0xDE, 0xAD, 0xBE, 0xEE]
		);
	}

	#[test]
	fn infer_digest_from_data_identifies_sha1() {
		assert_eq!(
			infer_digest_kind(&Vec::from_hex("5f4dcc3b5aa765d61d8327deb882cf99432aab3f").unwrap()).unwrap(),
			&ring::digest::SHA1_FOR_LEGACY_USE_ONLY
		);
	}

	#[test]
	fn infer_digest_from_data_does_not_support_crc() {
		assert_eq!(
			infer_digest_kind(&Vec::from_hex("3054285985").unwrap()).unwrap_err(),
			VdError::InvalidDigestLength { digest_length: 5 }
		);
	}

	#[test]
	fn read_json_accepts_4_bytes_len_len_bytes_msg() {
		let mut j: &[u8] = &[0x05, 0x00, 0x00, 0x00, b'{', b'a', b':', b'b', b'}'];

		assert_eq!(read_message(&mut j).unwrap(), "{a:b}")
	}

	#[test]
	fn read_json_rejects_unexpected_eof() {
		let mut j: &[u8] = &[0xFF, 0x00, 0x00, 0x00, b'{', b'a', b':', b'b', b'}'];
		assert_eq!(
			read_message(&mut j).unwrap_err().to_string(),
			"failed to fill whole buffer while reading message from extension"
		);
	}

	#[test]
	fn read_json_rejects_negative_input_size() {
		let mut j: &[u8] = &[0x00, 0x00, 0x00, 0xFF, b'{', b'a', b':', b'b', b'}'];

		assert_eq!(
			read_message(&mut j).unwrap_err().to_string(),
			"out of range integral type conversion attempted while parsing input"
		);
	}

	#[test]
	fn respond_to_extension_formats_data_correctly() {
		let j: &[u8] = &[0x05, 0x00, 0x00, 0x00, b'{', b'a', b':', b'1', b'}'];
		let mut w = vec![];

		respond_to_extension(r#"{a:1}"#, &mut w).unwrap();
		assert_eq!(w, j);
	}

	#[test]
	fn get_original_filename_returns_original_filename() {
		let obj: serde_json::value::Value = json!({
				"input-file": "/path/to/renamed file.f",
				"original-filename": "orig.f"
		});
		let p: VdMessage = serde_json::from_str(&obj.to_string()).unwrap();
		assert_eq!(p.get_original_filename().unwrap(), "orig.f");
	}

	#[test]
	fn get_original_filename_falls_back_to_input_filename() {
		let obj: serde_json::value::Value = json!({
				"input-file": "/path/to/orig.f",
		});
		let p: VdMessage = serde_json::from_str(&obj.to_string()).unwrap();
		assert_eq!(p.get_original_filename().unwrap(), "orig.f");
	}

}
