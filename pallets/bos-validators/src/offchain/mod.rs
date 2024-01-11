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
use sp_runtime::DispatchResult;
use sp_std::collections::BTreeMap;
use sp_io::offchain_index;

#[derive(Debug, Deserialize, Encode, Decode, Default)]
struct IndexingData(Vec<u8>, u64);

pub mod types;

impl<T: Config> Pallet<T> {
	pub fn execute_threshold_offchain_worker(
		block_number: u64,
		config: types::ThresholdConfig,
	) -> OffchainResult<()> {
		//let current_pool_address = CurrentPoolAddress::<T>::get();

		let current_pub_key = current_pub_key();

		if current_pub_key.is_none() {
			Self::initiate_keygen(config);
		}
		
		// TODO : Rotation needs to be handled
		// Sudo initiates the rotation
		// Sudo finishes the rotation and this will replace the current pub key with new pub key
		// The old pub key will remain until the new pub key is ready to be replace
		// Rotation needs to handle the boston wallet
		// --- Rotation process for boston wallet ----
		// Who can initiate rotation? Should be manual and initiated by Governance
		// 1. We need a pause function and unpause function, this will pause all boston related pallets, callable by admin role
		// 2. We need an admin role, this account can pause/unpause the boston pallets
		// 3. Admin can initiate the rotation, this create the new pub key, but not active
		// 4. Governance request to switch to new pub key from old pub key, this should transfer all amount in old wallet to new wallet.
		// 5. Set force origin as democracy for all boston pallets


		Ok(())
	}

	pub fn initiate_keygen(config: types::ThresholdConfig) -> DispatchResult {
		// if we have all round 1 shares, start round 2
		let round_1_shares = Round1Shares::<T>::iter().len();
		let round_2_shares = Round2Shares::<T>::iter().len();

		let required_key_threshold = CurrentQuorom::<T>::get().iter().count();
		if round_2_shares >= required_key_threshold {
			keygen_complete(config);
		} else if round_1_shares >= required_key_threshold {
			keygen_round_two(config);
		} else {
			keygen_round_one(config);
		}
	}

	pub fn keygen_round_one(config: types::ThresholdConfig) -> DispatchResult {
		let participants = CurrentQuorom::<T>::get();
		let threshold = CurrentPoolThreshold::<T>::get();

		// Ensure we have not already done round 1
		let our_round_one = Round1Shares::<T>::get(
			receiver_participant_identifier,
			participant_identifier,
			round1_package,
		);

		if our_round_one.is_some() {
			return Ok(())
		}

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

		let (round1_secret_package, round1_package) = frost::keys::dkg::part1(
			participant_identifier,
			participants.len(),
			threshold,
			&mut rng,
		)?;

		// Store the participant's secret package for later use.
		// In practice each participant will store it in their own environment.
		round1_secret_packages.insert(participant_identifier, round1_secret_package);

		// "Send" the round 1 package to all other participants.
		for receiver_participant_index in 1..=participants.len() {
			if receiver_participant_index == participant_index {
				continue
			}
			let receiver_participant_identifier: frost::Identifier =
				receiver_participant_index.try_into().expect("should be nonzero");

			// push everyone shares to storage
			// TODO : Does not have to be per participant since its on chain
			Round1Shares::<T>::insert(
				receiver_participant_identifier,
				participant_identifier,
				round1_package,
			);
		}

		// save our round1 secret to offchain worker storage
		let key = Self::derived_storage_key(frame_system::Module::<T>::block_number());
		let data = IndexingData(b"round_1_share".to_vec(), number);
		offchain_index::set(&key, &data.encode());

		Ok(())
	}

	pub fn keygen_round_two(config: types::ThresholdConfig) -> DispatchResult {
		let participants = CurrentQuorom::<T>::get();
		let threshold = CurrentPoolThreshold::<T>::get();

		// Ensure we did not already complete round 2
		let our_round_two = Round1Shares::<T>::get(
			receiver_participant_identifier,
			participant_identifier,
			round1_package,
		);

		if our_round_two.is_some() {
			return Ok(())
		}

		// TODO : Ensure this key can be saved and restored
		// TODO : Ensure this can be extracted via CLI
		// TODO : Research starting the protocol from round2
		// TODO : Cancel the keygen and start new, can be controlled by the admin role
		// threshold -> [Alice, Bob, Charlie]
		// admin needs to remove the faulty node
		// pause should also stop the keygen process
		// process to restore our secret share
		let mut round2_secret_packages = BTreeMap::new();

		// tool to query the quorom that checks availability of quorom members
		// 
		// threshold keygen -> [Alice, Bob, Charlie] 
		// btc wallet => [threshold, x, y, z, a, b, c] 

		////////////////////////////////////////////////////////////////////////////
		// Key generation, Round 2
		////////////////////////////////////////////////////////////////////////////
		let participant_index = participants.find_by_index(caller).unwrap();
		let participant_identifier = participant_index.try_into().expect("should be nonzero");

		// get all shares sent to us
		let round_1_packages = Round1Shares::<T>::iter_prefix(participant_index);

		// get our round1 secret from offchain worker storage
		// TODO : Use seperate keys
		let storage_key = Self::derived_storage_key(frame_system::Module::<T>::block_number());
		let data = IndexingData(b"round_1_share".to_vec(), number);
		let round1_secret_package = offchain_index::get(&key);

		let pub_key = Self::derived_signer_key(frame_system::Module::<T>::block_number());

		// ANCHOR: dkg_part2
		let (round2_secret_package, round2_packages) =
			frost::keys::dkg::part2(round1_secret_package, round1_packages)?;
		// ANCHOR_END: dkg_part2

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
			Round2Shares::<T>::insert(receiver_participant_identifier, participant_identifier, tag);
		}

		// save our round2 secret to offchain worker storage
		// TODO : Change to seperate key without dependency on block number
		let key = Self::derived_storage_key(frame_system::Module::<T>::block_number());
		let data = IndexingData(b"round_2_share".to_vec(), number);
		offchain_index::set(&key, &data.encode());

		Ok(())
	}

	pub fn keygen_complete(config: types::ThresholdConfig) -> DispatchResult {
		let participants = CurrentQuorom::<T>::get();

		// TODO : Move this to DB
		let mut round2_secret_packages = BTreeMap::new();

		////////////////////////////////////////////////////////////////////////////
		// Key generation, Round 2
		////////////////////////////////////////////////////////////////////////////
		let participant_index = participants.find_by_index(caller).unwrap();
		let participant_identifier = participant_index.try_into().expect("should be nonzero");

		// get all shares sent to us
		let round_1_packages = Round1Shares::<T>::iter_prefix(participant_index);
		let round_2_packages = Round2Shares::<T>::iter_prefix(participant_index);

		// get our round2 secret to offchain worker storage
		// KeygenID 
		let storage_key = Self::derived_storage_key(frame_system::Module::<T>::block_number());
		let pub_key_for_encryption = Self::derived_signer_key(frame_system::Module::<T>::block_number());
		let round1_secret_package = offchain_index::get(&storage_key);

		for package in round_2_packages {
			// decrypt key share
			let secret_key = SecretKey::from(pub_key_for_encryption);
			let public_key = PublicKey::from(receiver_participant_index);
			// TODO : read from Storage, do not generate here
			let nonce = GenericArray::from_slice(random_nonce());
			let mut buffer = round_1_package.to_vec();

			let round2_package = <Box>::new(&public_key, &secret_key)
				.decrypt(nonce, round_2_packages, &mut buffer)
				.unwrap();
				round_2_packages.push(round2_package)
		}
		
		let (key_package, pubkey_package) =
			frost::keys::dkg::part3(round2_secret_package, round1_packages, round2_packages)?;

		// push the key to storage
		CurrentPubKey::<T>::set(pubkey_package);

		// TODO : Events needed here to see the status of the keygen process

		Ok(())
	}

	pub fn derived_storage_key(block_number : BlockNumberFor<T>) -> Vec<u8> {
		const ONCHAIN_TX_KEY: &[u8] = b"bos_validators::key";
		let key : Vec<u8> = Default::default();
		key.extend(ONCHAIN_TX_KEY);
		key.extend(block_number.encode());
		key
	}

	pub fn derived_signer_key(block_number: BlockNumberFor<T>) -> Vec<u8> {
		let signer = Signer::<T, <T as Config>::OffChainAuthId>::all_accounts();
		if !signer.can_sign() {
			return Err(
				"No local accounts available. Consider adding one via `author_insertKey` RPC.",
			)
		}

		return signer.raw_key();
	}
}
