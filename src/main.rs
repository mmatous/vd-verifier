/*******************************************************************************
	vd-verifier — a companion application to vd.
	Copyright © 2019 Martin Matous
	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.
	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.
	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/******************************************************************************/
/******************************************************************************/

#[macro_use]
extern crate failure;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use failure::Error;
use hex::FromHex;
use md5::{Digest, Md5};
use serde_json::Value;
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::{fs, io};
use structopt::StructOpt;

macro_rules! s {
	($string_literal: tt) => {
		$string_literal.to_string()
	};
}

macro_rules! p {
	($to_path: expr) => {
		Path::new($to_path)
	};
}

#[derive(Debug, Fail)]
enum VdError {
	#[fail(display = "missing required data: {}", _0)]
	NoneError(String),
	#[fail(display = "received invalid parameter: {}", _0)]
	InvalidParam(String),
}

#[derive(Debug, PartialEq, Clone)]
struct HexData(Vec<u8>); // cannot accept Vec<_> in structopt otherwise
impl FromStr for HexData {
	type Err = hex::FromHexError;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		Vec::from_hex(s).map(Self)
	}
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum DigestKind {
	Md5,
	Sha1,
	Sha256,
	Sha512,
}

fn infer_digest_from_data(digest: &[u8]) -> Option<DigestKind> {
	match digest.len() {
		16 => Some(DigestKind::Md5),    // 128/8
		20 => Some(DigestKind::Sha1),   // 160/8
		32 => Some(DigestKind::Sha256), // 256/8
		64 => Some(DigestKind::Sha512), // 512/8
		_ => None,
	}
}

fn digest_input<R: std::io::Read>(input: &mut R, digest_kind: DigestKind) -> Result<Vec<u8>, Error> {
	match digest_kind {
		DigestKind::Md5 => calculate::<Md5, R>(input),
		DigestKind::Sha1 => calculate::<Sha1, R>(input),
		DigestKind::Sha256 => calculate::<Sha256, R>(input),
		DigestKind::Sha512 => calculate::<Sha512, R>(input),
	}
}

fn calculate<D: Digest + std::io::Write, R: std::io::Read>(input: &mut R) -> Result<Vec<u8>, Error> {
	let mut hasher = D::new();
	let _n = io::copy(input, &mut hasher)?;
	let hash = hasher.result();
	Ok(hash.to_vec())
}

fn json_to_options(json: &str) -> Result<String, Error> {
	let v: Value = serde_json::from_str(json)?;
	let obj = v
		.as_object()
		.ok_or_else(|| VdError::NoneError(s!("input is not a valid json object")))?;
	let mut res: String = s!("vd");
	for key in obj.keys() {
		let val = &obj[key].to_string();
		res.push_str(&format!(" --{} {}", key, val.trim_matches('"')));
	}
	Ok(res)
}

fn respond_to_extension<W: std::io::Write>(response: &str, writer: &mut W) -> Result<(), Error> {
	writer.write_i32::<LittleEndian>(response.as_bytes().len() as i32)?;
	writer.write_all(response.as_bytes())?;
	Ok(())
}

fn read_json_message<R: std::io::Read>(reader: &mut R) -> Result<String, Error> {
	let request_length = reader.read_i32::<LittleEndian>()?;
	if request_length < 1 {
		Err(VdError::InvalidParam(s!(request_length)))?;
	}
	let mut buffer = vec![0_u8; request_length as usize];
	reader.read_exact(buffer.as_mut_slice())?; //
	Ok(String::from_utf8(buffer)?)
}

fn receive_from_extension<R: std::io::Read>(reader: &mut R) -> Result<String, Error> {
	let extension_request = read_json_message(reader)?;
	json_to_options(&extension_request)
}

fn is_version_request(extension_request: &str) -> bool {
	extension_request == "vd --ping versionRequest"
}

fn process_incoming_message() -> Result<String, Error> {
	let extension_request = receive_from_extension(&mut io::stdin())?;
	if is_version_request(&extension_request) {
		let r = env!("CARGO_PKG_VERSION");
		return Ok(s!(r));
	}
	let msg = ParsedMessage::from_str(&extension_request)?;
	let provided_digest = msg.get_digest()?;
	let digest_kind =
		infer_digest_from_data(&provided_digest).ok_or_else(|| VdError::NoneError(s!("cannot infer digest kind")))?;
	let mut input_file = fs::File::open(msg.input_file)?;
	let calculated_digest = digest_input(&mut input_file, digest_kind)?;
	if calculated_digest == provided_digest {
		return Ok(s!("i"));
	}
	Ok(s!("f"))
}

#[derive(StructOpt, Debug)]
#[structopt(
	name = "vd-verifier",
	about = "Native app for use with vd browser extension",
	rename_all = "kebab-case"
)]
struct ParsedMessage {
	/// File name as supplied by the server
	#[structopt(short = "o", long)]
	original_filename: Option<PathBuf>,

	/// Absolute path to downloaded file
	#[structopt(short = "i", long)]
	input_file: PathBuf,

	/// File containing digest
	#[structopt(short = "d", long)]
	digest_file: Option<PathBuf>,

	/// Hex-encoded digest of input-file supplied directly
	#[structopt(short = "h", long)]
	digest_direct: Option<HexData>,

	/// File containing signed digest of input-file
	#[structopt(short = "s", long)]
	sig_file: Option<PathBuf>,

	/// File containing signed digest of input-file
	#[structopt(short = "c", long)]
	cleanup: bool,
}

impl ParsedMessage {
	pub fn from_str(message_string: &str) -> Result<Self, Error> {
		let m = Self::from_iter_safe(message_string.split(' '))?;
		Ok(m)
	}

	pub fn get_digest(&self) -> Result<Vec<u8>, Error> {
		if let Some(digest) = &self.digest_direct {
			return Ok(digest.0.clone());
		}
		let path = self
			.digest_file
			.as_ref()
			.ok_or_else(|| VdError::NoneError(s!("digest file path")))?;
		let f = fs::File::open(&path)?;
		self.search_digest_file(f)
	}

	fn search_digest_file<R: std::io::Read>(&self, file: R) -> Result<Vec<u8>, Error> {
		let f = BufReader::new(file);
		let orig_filename = self
			.original_filename
			.as_ref()
			.ok_or_else(|| VdError::NoneError(s!("original filename")))?;
		for line in f.lines() {
			let line = line?;
			let result = self.search_line(&line, orig_filename);
			if result.is_ok() {
				return result;
			};
		}
		Err(VdError::NoneError(s!("digest not present in file")))?
	}

	fn search_line(&self, line: &str, orig_filename: &Path) -> Result<Vec<u8>, Error> {
		let tokens: Vec<&str> = line.split_whitespace().collect();
		if tokens.len() < 2 {
			return Err(VdError::NoneError(s!("")))?;
		}
		let digest = tokens[0];
		let filename = tokens[1].trim_matches('*'); // * is possible filename prefix in sha*sums files
		if p!(filename).file_name().unwrap() == orig_filename {
			let decoded = hex::decode(digest)?;
			return Ok(decoded);
		}
		Err(VdError::NoneError(s!("")))?
	}
}

fn respond_error(e: &Error) -> Result<(), Error> {
	// {{ in rust format string -> {
	respond_to_extension(&format!(r#"{{"error": "{}"}}"#, e), &mut io::stdout())
}

fn respond_result(result: &str) -> Result<(), Error> {
	respond_to_extension(&format!(r#"{{"result": "{}"}}"#, result), &mut io::stdout())
}

fn main() -> Result<(), Error> {
	match process_incoming_message() {
		Ok(result) => respond_result(&result),
		Err(e) => respond_error(&e),
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn get_digest_returns_data_if_digest_specified_directly() {
		const S: &str = "vd -i /path/to/renamed.f -h DEADBEEF";

		let p = ParsedMessage::from_str(S).unwrap();
		assert_eq!(p.get_digest().unwrap(), vec! {0xDE, 0xAD, 0xBE, 0xEF});
	}

	#[test]
	fn get_digest_returns_error_if_message_has_no_digest() {
		const S: &str = "vd -o orig_name -i /path/to/renamed.f";

		assert_eq!(
			format!("{}", ParsedMessage::from_str(S).unwrap().get_digest().unwrap_err()),
			"missing required data: digest file path"
		);
	}

	#[test]
	fn search_file_returns_error_if_digest_passed_in_file_and_no_original_filename() {
		const S: &str = "vd -i /path/to/renamed.f -d /path/to/digest";
		let file: &[u8] = b"DEADBEEF *./file";

		assert_eq!(
			format!(
				"{}",
				ParsedMessage::from_str(S)
					.unwrap()
					.search_digest_file(file)
					.unwrap_err()
			),
			"missing required data: original filename"
		);
	}

	#[test]
	fn search_file_returns_error_if_digest_file_does_not_contain_digests() {
		const S: &str = "vd -o orig_name -i /path/to/renamed.f -d /path/to/digest";
		let file: &[u8] = b"not_hexdata *./file";

		assert_eq!(
			format!(
				"{}",
				ParsedMessage::from_str(S)
					.unwrap()
					.search_digest_file(file)
					.unwrap_err()
			),
			"missing required data: digest not present in file"
		);
	}

	#[test]
	fn digest_input_can_calculate_sha512() {
		let mut i: &[u8] = b"content to sha512\n";
		assert_eq!(
			digest_input(&mut i, DigestKind::Sha512).unwrap(),
			Vec::from_hex(
				"d43cb55cf99c1d726c9cf3cd4933171010db15afddff2f9cf612f3af2904b624dcb2ce\
				 7c3531b3193069d6bae487ed152b9d389b24b973d4f7460a95ed14e8e7"
			)
			.unwrap()
		);
	}

	#[test]
	fn search_line_accepts_shasums_format() {
		const S: &str = "vd -i /path/to/renamed.f -h DEADBEEF";

		let p = ParsedMessage::from_str(S).unwrap();
		assert_eq!(
			p.search_line("DEADBEEE *processed.file", p!("processed.file")).unwrap(),
			vec! {0xDE, 0xAD, 0xBE, 0xEE}
		);
	}

	#[test]
	fn infer_digest_from_data_identifies_md5() {
		assert_eq!(
			infer_digest_from_data(&Vec::from_hex("5f4dcc3b5aa765d61d8327deb882cf99").unwrap()),
			Some(DigestKind::Md5)
		);
	}

	#[test]
	fn infer_digest_from_data_does_not_support_crc() {
		assert_eq!(infer_digest_from_data(&Vec::from_hex("3054285985").unwrap()), None);
	}

	#[test]
	fn json_to_options_returns_cmdline_like_options() {
		assert_eq!(
			json_to_options(
				r#"{
									"original-filename": "orig_name",
			                        "input-file": "/path/to/renamed.f",
									"digest-file": "/path/to/digest"
			                        }"#
			)
			.unwrap(),
			r#"vd --digest-file /path/to/digest --input-file /path/to/renamed.f --original-filename orig_name"#
		);
	}

	#[test]
	fn read_json_accepts_4_bytes_len_len_bytes_msg() {
		let mut j: &[u8] = &[0x05, 0x00, 0x00, 0x00, b'{', b'a', b':', b'b', b'}'];

		assert_eq!(read_json_message(&mut j).unwrap(), "{a:b}")
	}

	#[test]
	#[should_panic]
	fn read_json_rejects_unexpected_eof() {
		let mut j: &[u8] = &[0xFF, 0x00, 0x00, 0x00, b'{', b'a', b':', b'b', b'}'];

		read_json_message(&mut j).unwrap();
	}

	#[test]
	#[should_panic]
	fn read_json_rejects_negative_input_size() {
		let mut j: &[u8] = &[0x00, 0x00, 0x00, 0xFF, b'{', b'a', b':', b'b', b'}'];

		read_json_message(&mut j).unwrap();
	}

	#[test]
	fn respond_to_extension_formats_data_correctly() {
		let j: &[u8] = &[0x05, 0x00, 0x00, 0x00, b'{', b'a', b':', b'1', b'}'];
		let mut w = vec![];

		respond_to_extension(r#"{a:1}"#, &mut w).unwrap();
		assert_eq!(w, j);
	}

}
