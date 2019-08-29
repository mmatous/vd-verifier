extern crate sequoia_openpgp as openpgp;

use openpgp::parse::Parse;
use failure::Error;
use openpgp::parse::stream::*;
use openpgp::tpk::TPKParser;
use openpgp::TPK;
use std::path::Path;

struct Helper<'a> {
	_results: Vec<VerificationResult<'a>>,
}

fn matching_keys_filter(tpk: &TPK, ids: &[openpgp::KeyID]) -> bool {
	eprintln!("looking for {:?} in {:?}", tpk, ids);
	for id in ids {
		if tpk.primary().key().keyid() == *id {
			eprintln!("primary matches");
			return true;
		}
		for binding in tpk.subkeys() {
			if binding.key().keyid() == *id {
				eprintln!("subkey matches");
				return true;
			}
		}
	}
	eprintln!("no matches");
	false
}

impl<'a> VerificationHelper for Helper<'a> {
	fn get_public_keys(&mut self, ids: &[openpgp::KeyID]) -> openpgp::Result<Vec<openpgp::TPK>> {
		let mut keys = Vec::new();
		// .kbx keyrings are currently not supported in sequoia
		// https://gitlab.com/sequoia-pgp/sequoia/issues/252
		let filtered_keys: Vec<_> =
			TPKParser::from_file(dirs::home_dir().expect("home dir").join(".gnupg/pubring.kbx"))?
				.unvalidated_tpk_filter(|tpk, _| matching_keys_filter(tpk, ids))
				.collect();
		eprintln!("filtered: {:?}", &filtered_keys);
		for tpk_result in filtered_keys {
			match tpk_result {
				Ok(tpk) => keys.push(tpk),
				Err(err) => {
					eprintln!("Error reading keyring: {}", err);
				}
			}
		}
		Ok(keys)
	}

	fn check(&mut self, structure: &MessageStructure) -> openpgp::Result<()> {
		// In this function, we implement our signature verification
		// policy.

		let mut good = false;
		for (i, layer) in structure.iter().enumerate() {
			match (i, layer) {
				// First, we are interested in signatures over the
				// data, i.e. level 0 signatures.
				(0, MessageLayer::SignatureGroup { ref results }) => {
					// Finally, given a VerificationResult, which only says
					// whether the signature checks out mathematically, we apply
					// our policy.
					match results.get(0) {
						Some(VerificationResult::GoodChecksum(..)) => good = true,
						Some(VerificationResult::MissingKey(_)) => bail!("No public key"),
						Some(VerificationResult::BadChecksum(_)) => bail!("Bad signature"),
						None => bail!("No signature"),
					}
				}
				_ => bail!("Unexpected message structure"),
			}
		}

		if good {
			Ok(()) // Good signature.
		} else {
			Err(failure::err_msg("Signature verification failed"))
		}
	}
}

pub fn verify_signatures(input_file: &Path, signature_file: &Path) -> Result<Vec<String>, Error> {
	let helper = Helper { _results: Vec::new() };
	let _verifier = DetachedVerifier::from_file(signature_file, input_file, helper, None)?;

	Ok(vec!["ok".to_string()])
}
