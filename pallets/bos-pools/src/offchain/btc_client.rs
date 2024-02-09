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
use crate::SignatureMap;
use bitcoin::{
	bech32::FromBase32,
	blockdata::{opcodes::all, script::Builder},
	psbt::{Prevouts, TapTree},
	util::{
		key::Secp256k1,
		sighash::{ScriptPath, SighashCache},
		taproot::{LeafVersion, TaprootBuilder},
	},
	Address, OutPoint, SchnorrSig, SchnorrSighashType, Script, Transaction, TxIn, TxOut, Txid,
	Witness, XOnlyPublicKey,
};
use electrum_client::{Client, ElectrumApi, ListUnspentRes};
use ferrum_primitives::BTC_OFFCHAIN_SIGNER_KEY_TYPE;
use frame_system::offchain::Signer;
use reqwest;
use sp_core::{ed25519, sr25519, ByteArray, Pair, Public, H256};
use sp_io::crypto::{ecdsa_generate, ecdsa_sign_prehashed, sr25519_generate, sr25519_sign};
use sp_std::str::FromStr;

const MAX_PERMITTED_FEE_IN_SATS: u64 = 100_000;

#[derive(Debug, Clone)]
pub struct BTCClient {
	pub http_api: Vec<u8>,
}

impl BTCClient {
	/// Generate a BTC pool address based on the provided validators' public keys.
	///
	/// This function constructs a BTC pool address using the taproot scheme with the given
	/// validators' public keys. It ensures connectivity to the BTC client, generates taproot
	/// scripts, and creates a taproot address for the BTC pool.
	pub fn generate_pool_address_from_signers(validators: Vec<Vec<u8>>) -> Result<Vec<u8>, String> {
		let secp = Secp256k1::new();

		// ensure we can connect to BTC Client
		let btc_client =
			Client::new(self.http_api.clone()).expect("Cannot establish connection to BTC Client!");

		let taproot_scripts = Self::generate_taproot_scripts(validators);

		let builder = TaprootBuilder::with_huffman_tree(vec![
			(1, taproot_scripts[0].clone()),
			(1, taproot_scripts[1].clone()),
		])
		.unwrap();
		let tap_tree = TapTree::from_builder(builder).unwrap();
		let pool_pub_key = XOnlyPublicKey::from_slice(&[0; 32]).unwrap();
		let tap_info = tap_tree.into_builder().finalize(&secp, pool_pub_key).unwrap();
		let merkle_root = tap_info.merkle_root();

		let address = Address::p2tr(
			&secp,
			tap_info.internal_key(),
			tap_info.merkle_root(),
			bitcoin::Network::Testnet,
		);

		log::info!("BTC Pools : Taproot calculated address {:?}", address);

		Ok(address)
	}

	/// Generate a Bitcoin transaction based on a withdrawal request from the BTC pool.
	///
	/// This function constructs a Bitcoin transaction for a withdrawal request, including inputs,
	/// outputs, and fees. It uses the taproot scheme and fetches relevant UTXOs to fund the
	/// transaction. The resulting transaction is returned on success.
	///
	/// # Parameters
	///
	/// - `recipient`: The recipient's Bitcoin address encoded as a vector of bytes.
	/// - `amount`: The amount to be withdrawn in satoshis.
	/// - `validators`: A vector containing public keys of validators participating in the BTC pool.
	/// - `current_pool_address`: The current pool's Bitcoin address encoded as a vector of bytes.
	///
	/// # Returns
	///
	/// Returns a `Result` with the constructed Bitcoin transaction on success, or an error message
	/// on failure.
	///
	/// # Errors
	///
	/// Returns a `String` error message if there are issues establishing a connection to the BTC
	/// client, if taproot-related operations fail, or if UTXO fetching encounters problems.
	///
	/// # Remarks
	///
	/// - The function uses the `Client` from the `bitcoin` crate to connect to the BTC client.
	/// - It constructs taproot scripts and calculates the taproot address for the BTC pool.
	/// - UTXOs are fetched using the constructed taproot address.
	/// - The transaction includes inputs, outputs, and fees based on the withdrawal request.
	/// - The calculated fees are logged, and the function returns the constructed transaction on
	///   success.
	pub fn generate_transaction_from_withdrawal_request(
		details: WithdrawalRequest,
	) -> Result<Transaction, String> {
		let secp = Secp256k1::new();

		// ensure we can connect to BTC Client
		let btc_client = Client::new("ssl://electrum.blockstream.info:60002")
			.expect("Cannot establish connection to BTC Client!");

		let taproot_scripts = Self::generate_taproot_scripts(validators);

		let builder = TaprootBuilder::with_huffman_tree(vec![
			(1, taproot_scripts[0].clone()),
			(1, taproot_scripts[1].clone()),
		])
		.unwrap();
		let tap_tree = TapTree::from_builder(builder).unwrap();
		let pool_pub_key = XOnlyPublicKey::from_slice(&[0u8; 32]).unwrap();
		let tap_info = tap_tree.into_builder().finalize(&secp, pool_pub_key).unwrap();
		let merkle_root = tap_info.merkle_root();

		let address = Address::p2tr(
			&secp,
			tap_info.internal_key(),
			tap_info.merkle_root(),
			bitcoin::Network::Testnet,
		);

		log::info!("BTC Pools : Taproot calculated address {:?}", address,);

		// if a previous transaction exists then we use those utxos, else we fetch new ones,
		// this will be triggered when we are retrying a transaction
		let mut utxos: Vec<Utxo> = Default::default();
		if Some(transaction) = details.get_latest_transaction() {
			utxos = transaction.candidate_utxos;
		} else {
			utxos = Self::fetch_utxos(address);
		}

		let tx_ins = Self::filter_needed_utxos(amount.into(), utxos);

		let recipient_address = String::from_utf8(recipient).expect("Found invalid UTF-8");
		let current_pool_address = String::from_utf8(address).expect("Found invalid UTF-8");

		let mut tx = Transaction {
			version: 2,
			lock_time: bitcoin::PackedLockTime(0),
			input: tx_ins
				.iter()
				.map(|tx| TxIn {
					previous_output: tx.previous_output.clone(),
					script_sig: Script::new(),
					sequence: bitcoin::Sequence(0xFFFFFFFF),
					witness: Witness::default(),
				})
				.collect::<Vec<_>>(),
			output: vec![
				TxOut {
					value: amount.into(),
					script_pubkey: Address::from_str(&recipient_address).unwrap().script_pubkey(),
				},
				TxOut {
					value: tx_ins.1 - amount as u64,
					script_pubkey: Address::from_str(&current_pool_address)
						.unwrap()
						.script_pubkey(),
				},
			],
		};

		let base_fees = Self::get_network_recommended_fee().unwrap();
		let total_fees = base_fees * tx.get_size() as u64;

		// account for fees in the change transaction
		tx.output[1].value = tx.output[1].value - total_fees;

		log::info!("BTC Pools : Calculated Fees {:?}", total_fees);

		let transaction_details = TransactionDetails {
			signatures: Default::default(),
			tx_id: None,
			tx_data: tx.encode(),
			fees: total_fees,
			candidate_utxos: Some(utxos),
			consumed_utxos: Some(tx_ins),
			prev_tx_hash: None,                           // this is our first transaction
			timeout_block: current_block_number + 24_u32, // 4hour timeout
			created_block: current_block_number,
		};

		Ok(transaction_details)
	}

	pub fn validate_tx_data_from_transaction_details(
		details: TransactionDetails,
	) -> Result<Transaction, String> {
		let validators = CurrentValidators::<T>::get();

		if validators.is_empty() {
			panic!("No BTC validators found!");
		}

		let taproot_scripts = Self::generate_taproot_scripts(validators);

		let builder = TaprootBuilder::with_huffman_tree(vec![
			(1, taproot_scripts[0].clone()),
			(1, taproot_scripts[1].clone()),
		])
		.unwrap();

		let tap_tree = TapTree::from_builder(builder).unwrap();
		let pool_pub_key = XOnlyPublicKey::from_slice(&[0u8; 32]).unwrap();
		let tap_info = tap_tree.into_builder().finalize(&secp, pool_pub_key).unwrap();
		let merkle_root = tap_info.merkle_root();
		let tx_ins = details.consumed_utxos;

		let address = Address::p2tr(
			&secp,
			tap_info.internal_key(),
			tap_info.merkle_root(),
			bitcoin::Network::Testnet,
		);

		let recipient_address = details.recipient;
		let current_pool_address = String::from_utf8(address).expect("Found invalid UTF-8");

		let recipient_address = String::from_utf8(recipient).expect("Found invalid UTF-8");
		let current_pool_address = String::from_utf8(address).expect("Found invalid UTF-8");

		let mut tx = Transaction {
			version: 2,
			lock_time: bitcoin::PackedLockTime(0),
			input: tx_ins
				.iter()
				.map(|tx| TxIn {
					previous_output: tx.previous_output.clone(),
					script_sig: Script::new(),
					sequence: bitcoin::Sequence(0xFFFFFFFF),
					witness: Witness::default(),
				})
				.collect::<Vec<_>>(),
			output: vec![
				TxOut {
					value: amount.into(),
					script_pubkey: Address::from_str(&recipient_address).unwrap().script_pubkey(),
				},
				TxOut {
					value: tx_ins.1 - amount as u64 - details.fees,
					script_pubkey: Address::from_str(&current_pool_address)
						.unwrap()
						.script_pubkey(),
				},
			],
		};

		// lets generate the hash and ensure it matches
		ensure!(tx.to_vec() == details.to_vec(), Error::<T>::TransactionValidationFailed);

		Ok(());
	}

	pub fn generate_taproot_scripts(validators: Vec<Vec<u8>>) -> Vec<Script> {
		// We create two scripts for taproot tree here

		// 1. First branch, this has a requirement that the transaction is always signed by the
		// threshold validator address, and in turn uses a lower threshold
		let script_with_threshold_required =
			Self::generate_taproot_script_with_required_signer(validators.clone());

		// 2. Second branch, this has a requirement that the transaction can be spend without
		// the signature of the required validator, but with a higher threshold limit
		let script_without_threshold_required =
			Self::generate_taproot_script_without_required_signer(validators.clone());

		vec![script_with_threshold_required, script_without_threshold_required]
	}

	/// Generate a Taproot script with a required signer and threshold model for additional signers.
	///
	/// This function constructs a Taproot script with a required first signer and a threshold model
	/// for additional signers. The first validator's public key is necessary for spending, and the
	/// rest follow a threshold model, where a certain number of additional signatures are required.
	///
	/// # Parameters
	///
	/// - `validators`: A vector containing public keys of validators participating in the threshold
	///   signature scheme.
	///
	/// # Returns
	///
	/// Returns a `Script` representing the generated Taproot script.
	pub fn generate_taproot_script_with_required_signer(validators: Vec<Vec<u8>>) -> Script {
		// we follow a simple approach here, the first validator is necessary, and the rest follow a
		// threshold model
		let mut wallet_script = Builder::new();

		// convert all validators pub key to XOnlyPubKey format
		let mut x_pub_keys = validators
			.iter()
			.map(|x| XOnlyPublicKey::from_slice(x).unwrap())
			.collect::<Vec<_>>();
		wallet_script.clone().push_x_only_key(&x_pub_keys.first().unwrap());
		wallet_script.clone().push_opcode(all::OP_CHECKSIGVERIFY);

		// calculate the threshold value
		// since one key is required, the threshold would be the remaining keys - 1
		let threshold = x_pub_keys.len() - 2;

		// add keys with OP_CHECKSIG for all keys except last
		for key in &mut x_pub_keys[1..threshold] {
			wallet_script.clone().push_x_only_key(&key);
			wallet_script.clone().push_opcode(all::OP_CHECKSIG);
		}

		// add the last key and threshold
		wallet_script.clone().push_x_only_key(&x_pub_keys.last().unwrap());
		wallet_script.clone().push_opcode(all::OP_CHECKSIGADD);
		wallet_script.clone().push_int(threshold as i64);
		wallet_script.clone().push_opcode(all::OP_GREATERTHANOREQUAL);

		wallet_script.into_script()
	}

	/// Generate a Taproot script without a required signer but with a threshold model for
	/// additional signers.
	///
	/// This function constructs a Taproot script without requiring a specific first signer, but
	/// instead, it follows a threshold model for additional signers. A certain number of signatures
	/// are required to spend from the Taproot script.
	///
	/// # Parameters
	///
	/// - `validators`: A vector containing public keys of validators participating in the threshold
	///   signature scheme.
	///
	/// # Returns
	///
	/// Returns a `Script` representing the generated Taproot script.
	pub fn generate_taproot_script_without_required_signer(validators: Vec<Vec<u8>>) -> Script {
		// We create two scripts for taproot tree here
		// we follow a simple approach here, the first validator is necessary, and the rest follow a
		// threshold model
		let mut wallet_script = Builder::new();

		// convert all validators pub key to XOnlyPubKey format
		let mut x_pub_keys = validators
			.iter()
			.map(|x| XOnlyPublicKey::from_slice(x).unwrap())
			.collect::<Vec<_>>();

		// calculate the threshold value
		// since one key is required, the threshold would be the remaining keys - 1
		let threshold = x_pub_keys.len() - 1;

		// add keys with OP_CHECKSIG for all keys except last
		for key in &mut x_pub_keys[0..threshold] {
			wallet_script.clone().push_x_only_key(&key);
			wallet_script.clone().push_opcode(all::OP_CHECKSIG);
		}

		// add the last key and threshold
		wallet_script.clone().push_x_only_key(&x_pub_keys.last().unwrap());
		wallet_script.clone().push_opcode(all::OP_CHECKSIGADD);
		wallet_script.clone().push_int(threshold as i64);
		wallet_script.clone().push_opcode(all::OP_GREATERTHANOREQUAL);

		wallet_script.into_script()
	}

	// TODO : Should wait for prev transaction to be broadcasted
	pub fn fetch_utxos(address: Address) -> Vec<ListUnspentRes> {
		let client = Client::new("ssl://electrum.blockstream.info:60002").unwrap();
		let tx_status = client.script_list_unspent(&address.script_pubkey()).unwrap();

		println!("Found UTXOS {:?}", vec_tx_in);

		vec_tx_in
	}

	pub fn check_txid_success(tx_id: Vec<u8>) -> bool {
		let client = Client::new("ssl://electrum.blockstream.info:60002").unwrap();
		let status = client.get_transaction_status(&tx_id).unwrap();

		println!("Found Status {:?}", status);

		status.confirmed
	}

	/// Filter and select the needed UTXOs (Unspent Transaction Outputs) to cover the specified
	/// amount.
	///
	/// This function takes a target amount and a list of available UTXOs, then filters and selects
	/// the UTXOs needed to cover the target amount. The UTXOs are sorted by age, and the oldest
	/// UTXOs are used first.
	///
	/// # Parameters
	///
	/// - `amount`: The target amount that needs to be covered by selecting UTXOs.
	/// - `available`: A vector of `ListUnspentRes` representing the available UTXOs.
	///
	/// # Returns
	///
	/// Returns a tuple containing a vector of `TxIn` representing the selected UTXOs as transaction
	/// inputs and the total amount covered by those UTXOs.
	pub fn filter_needed_utxos(
		amount: u64,
		mut available: Vec<ListUnspentRes>,
	) -> (Vec<TxIn>, u64) {
		let mut needed_utxos = vec![];
		let mut total_amount = 0;

		// sort by the oldest, we want to use the oldest first
		available.sort_by(|a, b| b.height.cmp(&a.height));

		for utxo in available {
			total_amount += utxo.value;

			needed_utxos.push(utxo);

			if total_amount >= amount {
				break
			}
		}

		let tx_ins = needed_utxos
			.iter()
			.map(|l| {
				return TxIn {
					previous_output: OutPoint::new(l.tx_hash, l.tx_pos.try_into().unwrap()),
					script_sig: Script::new(),
					sequence: bitcoin::Sequence(0xFFFFFFFF),
					witness: Witness::default(),
				}
			})
			.collect::<Vec<TxIn>>();

		(tx_ins, total_amount)
	}

	/// Broadcasts a completed Bitcoin transaction to the network.
	///
	/// This function takes a completed Bitcoin transaction, recipient information, transaction
	/// amount, signatures, and the current pool address to generate and broadcast the transaction
	/// to the Bitcoin network.
	///
	/// # Parameters
	///
	/// - `transaction`: The serialized byte representation of the completed Bitcoin transaction.
	/// - `recipient`: The recipient's Bitcoin address as a vector of bytes.
	/// - `amount`: The transaction amount in satoshis.
	/// - `signatures`: A map containing signatures from validators participating in the
	///   transaction.
	/// - `current_pool_address`: The current pool's Bitcoin address as a vector of bytes.
	///
	/// # Returns
	///
	/// Returns a `Result` containing the transaction ID (`Txid`) if the broadcast is successful, or
	/// an error message as a `String` in case of failure.
	pub fn broadcast_completed_transaction(details: TransactionDetails) -> Result<Txid, String> {
		// ensure we can connect to BTC Client
		let btc_client =
			Client::new(self.http_api.clone()).expect("Cannot establish connection to BTC Client!");

		let validators = signatures.clone().into_iter().map(|x| x.0).collect::<Vec<_>>();

		// == regenerate the transaction from details ===
		let taproot_scripts = Self::generate_taproot_scripts(validators);

		let builder = TaprootBuilder::with_huffman_tree(vec![
			(1, taproot_scripts[0].clone()),
			(1, taproot_scripts[1].clone()),
		])
		.unwrap();

		let tap_tree = TapTree::from_builder(builder).unwrap();
		let pool_pub_key = XOnlyPublicKey::from_slice(&[0u8; 32]).unwrap();
		let tap_info = tap_tree.into_builder().finalize(&secp, pool_pub_key).unwrap();
		let merkle_root = tap_info.merkle_root();
		let tx_ins = details.consumed_utxos;

		let address = Address::p2tr(
			&secp,
			tap_info.internal_key(),
			tap_info.merkle_root(),
			bitcoin::Network::Testnet,
		);

		let recipient_address = details.recipient;
		let current_pool_address = String::from_utf8(address).expect("Found invalid UTF-8");

		let recipient_address = String::from_utf8(recipient).expect("Found invalid UTF-8");
		let current_pool_address = String::from_utf8(address).expect("Found invalid UTF-8");

		let mut tx = Transaction {
			version: 2,
			lock_time: bitcoin::PackedLockTime(0),
			input: tx_ins
				.iter()
				.map(|tx| TxIn {
					previous_output: tx.previous_output.clone(),
					script_sig: Script::new(),
					sequence: bitcoin::Sequence(0xFFFFFFFF),
					witness: Witness::default(),
				})
				.collect::<Vec<_>>(),
			output: vec![
				TxOut {
					value: amount.into(),
					script_pubkey: Address::from_str(&recipient_address).unwrap().script_pubkey(),
				},
				TxOut {
					value: tx_ins.1 - amount as u64 - details.fees,
					script_pubkey: Address::from_str(&current_pool_address)
						.unwrap()
						.script_pubkey(),
				},
			],
		};

		// lets generate the hash and ensure it matches
		ensure!(tx.to_vec() == details.to_vec(), Error::<T>::TransactionValidationFailed);

		let prev_tx = tx
			.clone()
			.input
			.iter()
			.map(|tx_id| btc_client.transaction_get(&tx_id.previous_output.txid).unwrap())
			.collect::<Vec<Transaction>>();

		let tx_out_of_prev_tx =
			prev_tx.clone().iter().map(|tx| tx.output[0].clone()).collect::<Vec<TxOut>>();

		let prevouts = Prevouts::All(&transaction.consumed_utxos);
		let wallet_script =
			BTCClient::generate_taproot_script_with_required_signer(CurrentValidators::<T>::get());

		let key_sig = SighashCache::new(&mut tx.clone())
			.taproot_key_spend_signature_hash(0, &prevouts, SchnorrSighashType::Default)
			.unwrap();

		let actual_control = tap_info
			.control_block(&(wallet_script.clone(), LeafVersion::TapScript))
			.unwrap();

		let mut witnesses = vec![];

		// we need to insert the witness signatures in order
		// for this we arrange the signature map in the same order as the expected validator order
		let current_validators = CurrentValidators::<T>::get();
		let mut ordered_signatures = Vec::with_capacity(current_validators.iter().len());

		for (pos, validator_account) in current_validators.iter().enumerate() {
			let signature = signatures.get(validator_account);

			// if the validator has signed, then insert the signature in expected position
			if let Some(signature) = signature {
				ordered_signatures.insert(pos, signature);
			}
			// this means this validator has not signed, in this case we insert an empty vector
			else {
				ordered_signatures.insert(pos, vec![]);
			}
		}

		// here we loop in reverse since we are inserting to a stack, FIFO
		for signature in ordered_signatures.iter().rev() {
			witnesses.push(
				SchnorrSig {
					sig: secp256k1::schnorr::Signature::from_slice(&signature.1).unwrap(),
					hash_ty: SchnorrSighashType::Default,
				}
				.to_vec(),
			);
		}

		witnesses.push(taproot_script.to_bytes());
		witnesses.push(actual_control.serialize());

		let wit = Witness::from_vec(witnesses);

		for mut input in tx.clone().input.into_iter() {
			input.witness = wit.clone();
		}

		// final sanity checks, ensure our fee is sane
		// TODO : Improve this to that we increase fee when a tx is delayed
		let min_fees = btc_client.estimate_fee(tx.get_size());
		let rec_base_fees = Self::get_network_recommended_fee().unwrap();
		let total_fees = rec_base_fees * tx.get_size() as u64;

		if (total_fees > MAX_PERMITTED_FEE_IN_SATS) {
			panic!("Cannot spend fee above limit!")
		}

		log::info!("BTC Pools : Calculated Fees {:?}", total_fees);

		// Broadcast tx
		let tx_id = btc_client.transaction_broadcast(&tx).unwrap();
		println!("transaction hash: {}", tx_id.to_string());

		Ok(tx_id)
	}

	fn get_network_recommended_fee() -> Result<u64, ()> {
		let api_url = "https://api.blockchain.info/mempool/fees";

		#[derive(serde::Serialize, serde::Deserialize)]
		struct MempoolFees {
			regular: u64,
			priority: u64,
		}

		// Make the HTTP GET request
		let response: MempoolFees = reqwest::blocking::get(api_url).unwrap().json().unwrap();
		return Ok(response.regular)
	}

	fn is_transaction_successful(tx_id: Vec<u8>) -> bool {
		// ensure we can connect to BTC Client
		let btc_client =
			Client::new(self.http_api.clone()).expect("Cannot establish connection to BTC Client!");

		#[derive(serde::Serialize, serde::Deserialize)]
		struct TransactionGetResponse {
			blockhash: BlockHash,
			blocktime: u64,
			confirmations: u64,
			hash: Vec<u8>,
			hex: Vec<u8>,
			locktime: u64,
			size: u64,
			time: u64,
			txid: Vec<u8>,
			version: u8,
			vin: Vec<TxIn>,
			vout: Vec<TxOut>,
		};

		// refer https://electrumx-spesmilo.readthedocs.io/en/latest/protocol-methods.html#blockchain-transaction-get
		// always set verbose = true, else json serialisation fails
		let transaction_status = btc_client.transaction_get(&tx_id, true);

		match transaction_status {
			Ok(res) => {
				let transaction_status: TransactionGetResponse =
					transaction_status.unwrap().json().unwrap();
				// we require atleast 3 confirmations
				return transaction_status.confirmations > 3
			},
			Err(e) => {
				log::info!("Transaction success check failed with error {:?}", e);
				// we dont want to fail here since the api may return error if transaction is not
				// picked up
				return false
			},
		}
	}
}

// #[derive(Clone)]
pub struct BTCClientSignature {
	pub from: sr25519::Public,
	pub _signer: sr25519::Public,
}

impl BTCClientSignature {
	pub fn new(from: sr25519::Public, signer: &[u8]) -> Self {
		BTCClientSignature { from, _signer: sr25519::Public::try_from(signer).unwrap() }
	}

	pub fn sign(&self, hash: &[u8]) -> Result<sr25519::Signature, ()> {
		log::info!("Signer address is : {:?}", self.from);
		// TODO : We should handle this properly, if the signing is not possible maybe propogate the
		// error upstream
		let signed = sr25519_sign(BTC_OFFCHAIN_SIGNER_KEY_TYPE, &self.from, &hash).unwrap();
		Ok(signed)
	}
}

impl From<sr25519::Public> for BTCClientSignature {
	fn from(signer: sr25519::Public) -> Self {
		log::info!("PUBLIC KEY {:?}", signer);

		BTCClientSignature { _signer: signer, from: signer }
	}
}
