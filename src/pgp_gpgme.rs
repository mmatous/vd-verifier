use failure::{Error, ResultExt};
use gpgme::{Context, Protocol, VerificationResult};
use std::fs;
use std::path::Path;

macro_rules! ctx {
	($additional_context: expr) => {
		|err| format!("{} while {}", err, $additional_context)
	};
}

fn interpret_verify_result(result: &VerificationResult) -> Vec<String> {
	eprintln!("{:?}", result);
	let mut res = Vec::new();
	for signature in result.signatures() {
		let status = match signature.status() {
			Ok(()) => "PASS".to_string(),
			Err(e) => e.description().to_string(),
		};
		res.push(status);
	}
	res
}

pub fn verify_signatures(input_file: &Path, signature_file: &Path) -> Result<Vec<String>, Error> {
	let mut ctx = Context::from_protocol(Protocol::OpenPgp)?;

	let signature = fs::File::open(signature_file).with_context(ctx!("opening signature file"))?;
	let signed = fs::File::open(input_file).with_context(ctx!("opening input file for signature"))?;
	let result = ctx.verify_detached(signature, signed)?;
	Ok(interpret_verify_result(&result))
}
