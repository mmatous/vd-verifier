use serde::{Deserialize, Serialize};

#[macro_export]
macro_rules! s {
	($string_literal: tt) => {
		$string_literal.to_string()
	};
}

#[macro_export]
macro_rules! p {
	($to_path: expr) => {
		Path::new($to_path)
	};
}

#[macro_export]
macro_rules! ctx {
	($additional_context: expr) => {
		|err| format!("{} while {}", err, $additional_context)
	};
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "lowercase")]
pub struct Response {
	pub integrity: Result<IntegritySummary, String>,
	pub signatures: Result<Vec<String>, String>,
}

impl Default for Response {
	fn default() -> Self {
		Self {
			integrity: Ok(IntegritySummary::Untested),
			signatures: Ok(Vec::new()),
		}
	}
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "lowercase")]
pub struct ResponseVersion {
	version: String,
}

impl Default for ResponseVersion {
	fn default() -> Self {
		Self {
			version: env!("CARGO_PKG_VERSION").to_string(),
		}
	}
}

#[derive(Debug, Eq, Fail, Ord, PartialOrd, PartialEq)]
pub enum VdError {
	#[fail(display = "Missing required argument: {}", argument_name)]
	MissingArgument { argument_name: String },
	#[fail(display = "Invalid parameter: {}", param_name)]
	InvalidParam { param_name: String },
	#[fail(display = "Invalid digest length: {} bytes", digest_length)]
	InvalidDigestLength { digest_length: usize },
	#[fail(
		display = "{} is not well-formed or does not contain {}",
		file_type, missing_data
	)]
	MissingContent { file_type: String, missing_data: String },
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IntegritySummary {
	Pass,
	Fail,
	Untested,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "kebab-case")]
pub struct VersionRequest {
	version_request: bool,
}
