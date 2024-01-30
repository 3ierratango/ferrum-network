// Copyright 2019-2023 Ferrum Inc.
// This file is part of Ferrum.

// Ferrum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Ferrum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Ferrum.  If not, see <http://www.gnu.org/licenses/>.
use super::*;
use crate::Config;
use crypto_box::{
	aead::{generic_array::GenericArray, Aead, AeadInPlace, OsRng},
	PublicKey, SecretKey,
};
use curve25519_dalek::EdwardsPoint;
use frost_secp256k1 as frost;
use hex_literal::hex;
use rand::thread_rng;
use sp_io::offchain_index;
use sp_runtime::DispatchResult;
use sp_std::collections::BTreeMap;

#[derive(Debug, Deserialize, Encode, Decode, Default)]
struct IndexingData(Vec<u8>, u64);

pub mod types;

impl<T: Config> Pallet<T> {
	/// Executes the offchain worker for threshold-based operations.
	///
	/// This function is responsible for managing various offchain tasks based on the
	/// current state of the threshold-based key generation and signing process. It checks
	/// the status of the pallet, the need for key generation, and the signing queue to
	/// determine the appropriate actions to take.
	///
	/// # Parameters
	///
	/// - `block_number`: The current block number.
	/// - `config`: Configuration parameters for the threshold-based operations.
	///
	/// # Errors
	///
	/// Returns `Ok(())` if the offchain worker executes successfully.
	pub fn execute_threshold_offchain_worker(
		block_number: u64,
		config: types::ThresholdConfig,
	) -> OffchainResult<()> {
		let pallet_paused = IsPalletPaused::<T>::get();
		if pallet_paused {
			log::info!(
				"BOS Validators : Pallet paused, not executing all offchain worker functions!"
			);
		}

		let current_pub_key = current_pub_key();

		if current_pub_key.is_none() {
			Self::initiate_keygen(config, true);
		}
		// we need a new key to rotate
		else if ExecuteNextPubKey::<T>::get() {
			Self::initiate_keygen(config, false);
		}
		// something needs to be signed
		// only execute if pallet is not paused
		else if SigningQueue::<T>::get().is_some() && !pallet_paused {
			Self::initiate_signing(config);
		}
		// finally check for emergency signing queue
		// should execute even if pallet is paused
		else if EmergencySigningQueue::<T>::get().is_some() {
			Self::initiate_signing(config);
		}
		// even if paused we still allows signed transactions to be processed
		else if PartialSignatures::<T>::get().is_some() {
			Self::complete_signing(config);
		} else {
			return Ok(())
		}
	}

	pub fn initiate_keygen(config: types::ThresholdConfig, is_genesis: bool) -> DispatchResult {
		// if we have all round 1 shares, start round 2
		let round_1_shares = Round1Shares::<T>::iter().len();
		let round_2_shares = Round2Shares::<T>::iter().len();

		let required_key_threshold = if is_genesis {
			CurrentQuorom::<T>::get().iter().count();
		} else {
			NextQuorom::<T>::get().iter().count();
		};

		if round_2_shares >= required_key_threshold {
			keygen_complete(config);
		} else if round_1_shares >= required_key_threshold {
			keygen_round_two(config);
		} else {
			keygen_round_one(config);
		}
	}

	/// Executes the first round of the distributed key generation (DKG) process.
	///
	/// This function handles the generation and distribution of Round 1 key shares among
	/// participants. Each participant generates a secret package and a share of the key,
	/// and these shares are stored in the blockchain storage. Additionally, the function
	/// stores the participant's own Round 1 key share in offchain storage.
	///
	/// # Parameters
	///
	/// - `config`: Configuration parameters for the key generation process.
	/// - `is_genesis`: A boolean indicating whether the key generation is for the current genesis.
	///
	/// # Errors
	///
	/// Returns `Ok(())` if the first round of the key generation process completes successfully.
	pub fn keygen_round_one(config: types::ThresholdConfig, is_genesis: bool) -> DispatchResult {
		let participants = if is_genesis {
			CurrentQuorom::<T>::get();
		} else {
			NextQuorom::<T>::get();
		};

		let threshold = if is_genesis {
			CurrentPoolThreshold::<T>::get();
		} else {
			NextPoolThreshold::<T>::get();
		};

		let mut round1_secret_packages = BTreeMap::new();

		////////////////////////////////////////////////////////////////////////////
		// Key generation, Round 1
		////////////////////////////////////////////////////////////////////////////
		// Quorom : [Alice, Bob, Charlie]
		// Alice -> 0
		// Bob -> 1
		// Charlie -> 2
		let participant_index = participants.find_by_index(caller).unwrap();
		let participant_identifier = participant_index.try_into().expect("should be nonzero");

		// Ensure we have not already done round 1
		let our_round_one = Round1Shares::<T>::get(participant_identifier);

		if our_round_one.is_some() {
			return Ok(())
		}

		let (round1_secret_package, round1_package) = frost::keys::dkg::part1(
			participant_identifier,
			participants.len(),
			threshold,
			&mut rng,
		)?;

		// Store the participant's secret package for later use.
		// In practice each participant will store it in their own environment.
		round1_secret_packages.insert(participant_identifier, round1_secret_package);

		// push everyone shares to storage
		Round1Shares::<T>::insert(participant_identifier, round1_package);

		// save our round1 secret to offchain worker storage
		let key = Self::phase_one_storage_key();
		let data = IndexingData(b"round_1_share".to_vec(), number);
		offchain_index::set(&key, &data.encode());

		// Emit an event.
		Self::deposit_event(Event::Phase1ShareSubmitted { submitter: caller });

		Ok(())
	}

	/// Executes the second round of the distributed key generation (DKG) process.
	///
	/// This function handles the generation and distribution of Round 2 key shares among
	/// participants. Each participant encrypts their Round 2 key share using the public key
	/// of the receiving participant and submits the encrypted share to the storage. Additionally,
	/// the function stores the participant's own Round 2 key share in offchain storage.
	///
	/// # Parameters
	///
	/// - `config`: Configuration parameters for the key generation process.
	/// - `is_genesis`: A boolean indicating whether the key generation is for the current genesis.
	///
	/// # Errors
	///
	/// Returns `Ok(())` if the second round of the key generation process completes successfully.
	pub fn keygen_round_two(config: types::ThresholdConfig, is_genesis: bool) -> DispatchResult {
		let participants = if is_genesis {
			CurrentQuorom::<T>::get();
		} else {
			NextQuorom::<T>::get();
		};

		let threshold = if is_genesis {
			CurrentPoolThreshold::<T>::get();
		} else {
			NextPoolThreshold::<T>::get();
		};

		// Ensure we did not already complete round 2
		let our_round_two = Round2Shares::<T>::get(
			receiver_participant_identifier,
			receiver_participant_identifier,
		);

		if our_round_two.is_some() {
			return Ok(())
		}

		let mut round2_secret_packages = BTreeMap::new();

		////////////////////////////////////////////////////////////////////////////
		// Key generation, Round 2
		////////////////////////////////////////////////////////////////////////////
		let participant_index = participants.find_by_index(caller).unwrap();
		let participant_identifier = participant_index.try_into().expect("should be nonzero");

		// get all shares sent to us
		let round_1_packages = Round1Shares::<T>::iter();

		// get our round1 secret from offchain worker storage
		let storage_key = Self::phase_one_storage_key();
		let data = IndexingData(b"round_1_share".to_vec(), number);
		let round1_secret_package = offchain_index::get(&key);

		let pub_key = Self::derived_signer_key();

		let (round2_secret_package, round2_packages) =
			frost::keys::dkg::part2(round1_secret_package, round1_packages)?;

		// "Send" the round 2 package to all other participants.
		for receiver_participant_index in 1..=participants.len() {
			if receiver_participant_index == participant_index {
				continue
			}
			let receiver_participant_identifier: frost::Identifier =
				receiver_participant_index.try_into().expect("should be nonzero");

			// Fetch the receiver participants pub key
			// then encrypt with our private key
			let secret_key_for_encryption = SecretKey::from(pub_key);
			let participant_pub_key = participants.get(receiver_participant_index).1;
			let public_key_for_encryption = PublicKey::from(participant_pub_key);
			let nonce = GenericArray::from_slice(random_nonce());
			// TODO : Investigate the share sent
			let mut buffer = round_2_package.to_vec();

			let tag = <Box>::new(&public_key_for_encryption, &secret_key_for_encryption)
				.encrypt_in_place_detached(nonce, round_2_package, &mut buffer)
				.unwrap();

			// push everyone shares to storage
			Round2Shares::<T>::insert(
				receiver_participant_identifier,
				participant_identifier,
				(nonce, tag),
			);

			// Emit an event.
			Self::deposit_event(Event::Phase2ShareSubmitted {
				submitter: participant_identifier,
				recipient: receiver_participant_identifier,
			});
		}

		// save our round2 secret to offchain worker storage
		let key = Self::phase_two_storage_key();
		let data = IndexingData(b"round_2_share".to_vec(), number);
		offchain_index::set(&key, &data.encode());

		Ok(())
	}

	/// Completes the key generation process, producing the final public key.
	///
	/// This function handles the final steps of the distributed key generation (DKG) process,
	/// aggregating the key shares received from participants in both Round 1 and Round 2. The
	/// generated public key is then stored in the appropriate storage based on whether it is for
	/// the current genesis or the next one.
	///
	/// # Parameters
	///
	/// - `config`: Configuration parameters for the key generation process.
	/// - `is_genesis`: A boolean indicating whether the key generation is for the current genesis.
	///
	/// # Errors
	///
	/// Returns `Ok(())` if the key generation process completes successfully.
	pub fn keygen_complete(config: types::ThresholdConfig, is_genesis: bool) -> DispatchResult {
		let participants = if is_genesis {
			CurrentQuorom::<T>::get();
		} else {
			NextQuorom::<T>::get();
		};

		// TODO : Move this to DB
		let mut round2_secret_packages = BTreeMap::new();

		////////////////////////////////////////////////////////////////////////////
		// Key generation, Round 2
		////////////////////////////////////////////////////////////////////////////
		let participant_index = participants.find_by_index(caller).unwrap();
		let participant_identifier = participant_index.try_into().expect("should be nonzero");

		// get all shares sent to us
		let round_1_packages = Round1Shares::<T>::iter();
		let round_2_packages = Round2Shares::<T>::iter_prefix(participant_index);

		// get our round2 secret to offchain worker storage
		// KeygenID
		let storage_key = Self::phase_two_storage_key();
		let pub_key_for_encryption = Self::derived_signer_key();
		let round1_secret_package = offchain_index::get(&storage_key);

		for package in round_2_packages {
			// decrypt key share
			let secret_key = SecretKey::from(pub_key_for_encryption);
			let public_key = PublicKey::from(receiver_participant_index);
			let mut buffer = round_1_package.to_vec();

			let round2_package = <Box>::new(&public_key, &secret_key)
				.decrypt(round_2_packages.0, round_2_packages.1, &mut buffer)
				.unwrap();
			round_2_packages.push(round2_package)
		}

		let (key_package, pubkey_package) =
			frost::keys::dkg::part3(round2_secret_package, round1_packages, round2_packages)?;

		// push the key to storage
		if is_genesis {
			CurrentPubKey::<T>::set(pubkey_package);
		} else {
			NextPubKey::<T>::set(pubkey_package);
		};

		Self::deposit_event(Event::KeygenCompleted { pub_key: pubkey_package.to_vec() });

		Ok(())
	}

	/// Initiates the signing process.
	///
	/// This function generates a partial signature for the data in the Emergency Signing Queue
	/// and pushes it to the chain. The process involves creating a commitment share and signing
	/// the message hash with the participant's key.
	///
	/// # Parameters
	///
	/// - `config`: Configuration parameters for the signing process.
	///
	/// # Errors
	///
	/// Returns `Ok(())` if the signing process completes successfully.
	pub fn initiate_signing(config: types::ThresholdConfig) -> DispatchResult {
		let data_to_sign = EmergencySigningQueue::<T>::get();

		// initiate the round to all participants
		let participants = CurrentQuorom::<T>::get();

		let threshold = CurrentPoolThreshold::<T>::get();

		let participant_index = participants.find_by_index(caller).unwrap();
		let participant_identifier = participant_index.try_into().expect("should be nonzero");

		let key = Self::phase_two_storage_key();
		let data = IndexingData(b"round_2_share".to_vec(), number);
		let pk_sk = offchain_index::get(&key, &data.encode());

		// generate our partial signature and push to chain
		let nonce = GenericArray::from_slice(random_nonce());
		// first we generate our public keyshare
		let (p1_public_comshares, mut p1_secret_comshares) =
			frost::keys::dkg::generate_commitment_share_lists(nonce, &pk_sk, 1).unwrap();

		// sign the actual message and create the partial sig
		let message_hash = Secp256k1Sha256::h4(&data_to_sign[..]);
		let partial_sig = pk_sk
			.sign(
				&message_hash,
				0, // group key
				&mut p1_secret_comshares,
				0,
				participants.iter().collect::<Vec<_>>(),
			)
			.unwrap();

		PartialSignatures::<T>::push(participant_index, partial_sig);

		Ok(())
	}

	/// Completes the signing process.
	///
	/// This function is responsible for aggregating partial signatures received from participants,
	/// combining them into a final signature, and pushing the result to the Bos Pools pallet if
	/// the threshold is reached.
	///
	/// # Parameters
	///
	/// - `config`: Configuration parameters for the signing process.
	///
	/// # Errors
	///
	/// Returns `Ok(())` if the signing process completes successfully. If the number of partial
	/// signatures does not reach the required threshold, the function returns early without an
	/// error.
	pub fn complete_signing(config: types::ThresholdConfig) -> DispatchResult {
		let partial_signatures = PartialSignatures::<T>::get().unwrap();

		// initiate the round to all participants
		let participants = CurrentQuorom::<T>::get();
		let threshold = CurrentPoolThreshold::<T>::get();

		// exit early if we do not have enough partial signatures
		if partial_signatures.len() < threshold {
			return Ok(())
		}

		let data_to_sign = EmergencySigningQueue::<T>::get();
		let message_hash = Secp256k1Sha256::h4(&data_to_sign[..]);

		// if we reached threshold, combine all partial signatures
		let params = ThresholdParameters::new(participants.len(), threshold);
		let mut aggregator = SignatureAggregator::new(params, 0, &message[..]);

		for partial_sig in partial_signatures {
			aggregator.include_partial_signature(&partial_sig);
		}

		let aggregator = aggregator.finalize().unwrap();
		let final_signature = aggregator.aggregate().unwrap();

		// clean partial signature storage so next data can be signed
		PartialSignatures::<T>::clear();

		// push the signature to the bos pools pallet if needed
		// this is a hook, no need to wait for success
		let _ = T::BosPoolsHandler::register_signature(message_hash, final_signature);

		Ok(())
	}

	pub fn phase_one_storage_key() -> Vec<u8> {
		const PHASE_ONE_KEY: &[u8] = b"bos_validators::key";
		PHASE_ONE_KEY.to_vec()
	}

	pub fn phase_two_storage_key() -> Vec<u8> {
		const PHASE_ONE_KEY: &[u8] = b"bos_validators::key";
		PHASE_ONE_KEY.to_vec()
	}

	pub fn keyshare_storage_key() -> Vec<u8> {
		const PHASE_ONE_KEY: &[u8] = b"bos_validators::key";
		PHASE_ONE_KEY.to_vec()
	}

	pub fn derived_signer_key(block_number: BlockNumberFor<T>) -> Vec<u8> {
		let signer = Signer::<T, <T as Config>::OffChainAuthId>::all_accounts();
		if !signer.can_sign() {
			return Err(
				"No local accounts available. Consider adding one via `author_insertKey` RPC.",
			)
		}

		return signer.raw_key()
	}
}
