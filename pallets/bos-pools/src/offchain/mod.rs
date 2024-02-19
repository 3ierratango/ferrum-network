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
use crate::PendingWithdrawals;
use electrum_client::{Client, ElectrumApi};
use sp_runtime::traits::Zero;
pub mod types;
use crate::offchain::btc_client::BTCClientSignature;
use frame_system::offchain::Signer;
use sp_core::sr25519;
pub use types::*;

mod btc_client;
use btc_client::BTCClient;

// if timeout and tx not accepted, then retry
// 1. Withdrawal
// 2. Check Pending Transaction (not timed out)
// 3. Sign the pending tansaction
// 4. Create a new if not exists
// 3. Check (tx is submitted or timeout > now)
// 4. New Pending Transactin (only diff is fee amount, ensure we have same utxo)
// 5. Resign
// 6.

impl<T: Config> Pallet<T> {
	/// Execute the offchain worker for BTC Pools.
	///
	/// This function is responsible for processing pending withdrawal requests and pending
	/// transactions in the BTC Pools pallet. It checks for any withdrawals requested by users and
	/// processes them, and it also handles any pending BTC transactions by interacting with the
	/// specified BTC network based on the provided `btc_config`.
	///
	/// # Parameters
	///
	/// - `block_number`: The current block number.
	/// - `btc_config`: BTC network configuration used for processing pending transactions.
	///
	/// # Errors
	///
	/// Returns an `OffchainResult` indicating the success or failure of the offchain worker
	/// execution. In case of success, `Ok(())` is returned.
	///
	/// # Remarks
	///
	/// - If the pallet is paused (`IsPalletPaused` is set to true), the offchain worker is not
	///   executed.
	/// - Handles pending withdrawal requests by processing each withdrawal for the specified
	///   recipient.
	/// - Processes pending BTC transactions by interacting with the BTC network based on the
	///   provided `btc_config`.
	pub fn execute_btc_pools_offchain_worker(
		block_number: u64,
		btc_config: types::BTCConfig,
	) -> OffchainResult<()> {
		// if the pallet is paused, we dont execute the offchain worker
		let pallet_paused = IsPalletPaused::<T>::get();

		if pallet_paused {
			log::info!("BTC Pools : Pallet is paused");
			return Ok(())
		}

		// first handle any pending withdrawal requests
		let pending_withdrawal = PendingWithdrawals::<T>::iter().first();

		log::info!("BTC Pools : Pending withdrawals is {:?}", pending_withdrawals);
		if pending_withdrawal.is_none() {
			return Ok(())
		}

		let result = Self::handle_withdrawal_request(pending_withdrawal.unwrap(), btc_config);
		log::info!(
			"BTC Pools : Withdrawal request for recipient : {:?}, processed {:?}",
			recipient,
			result
		);

		Ok(())
	}

	/// Handle a withdrawal request for BTC Pools.
	///
	/// This function processes a withdrawal request by preparing a BTC transaction. The transaction
	/// includes the recipient's address, withdrawal amount, a list of known validators, and the
	/// current pool address. The generated transaction is then stored in the `PendingTransactions`
	/// storage, awaiting further processing by the offchain worker.
	///
	/// # Parameters
	///
	/// - `recipient`: The recipient's BTC address to which the withdrawal amount is sent.
	/// - `amount`: The amount of BTC to be withdrawn.
	///
	/// # Errors
	///
	/// Returns an `OffchainResult` indicating the success or failure of processing the withdrawal
	/// request. In case of success, `Ok(())` is returned.
	///
	/// # Remarks
	///
	/// - The function generates a BTC transaction using the provided withdrawal request details.
	/// - The transaction is stored in the `PendingTransactions` storage, awaiting offchain worker
	///   execution.
	/// - The `CurrentPoolAddress` and `RegisteredValidators` storages are used to gather necessary
	///   information.
	/// - If no BTC validators are found, the function panics with the message "No BTC validators
	///   found!"
	pub fn handle_withdrawal_request(
		pending_withdrawal: WithdrawalRequest<T>,
		btc_config: types::BTCConfig,
	) -> OffchainResult<()> {
		// handle depending on the stage of the withdrawal
		match pending_withdrawal.status {
			New => Self::handle_new_withdrawal_request(pending_withdrawal, btc_config),
			TransactionCreated => Self::handle_transaction_sign(pending_withdrawal, btc_config),
			TransactionSigned => Self::handle_transaction_broadcast(pending_withdrawal, btc_config),
			AwaitingConfirmation => Self::handle_transaction_retry(pending_withdrawal, btc_config),
			TransactionRetry => Self::handle_transaction_retry(pending_withdrawal, btc_config),
		}
	}

	pub fn handle_new_withdrawal_request(
		details: WithdrawalRequest<T>,
		btc_config: types::BTCConfig,
	) -> OffchainResult<()> {
		// pick all the known validators
		let validators = CurrentValidators::<T>::get();

		if validators.is_empty() {
			panic!("No BTC validators found!");
		}

		let now = <T as frame_system::Config>::block_number();

		let transaction =
			btc_client::BTCClient::generate_transaction_from_withdrawal_request(details)
				.unwrap()
				.txid()
				.as_ref()
				.to_vec();

		let signer = Signer::<T, T::AuthorityId>::all_accounts();
		if !signer.can_sign() {
			return Err(
				"No local accounts available. Consider adding one via `author_insertKey` RPC.",
			)
		}

		
		let results = signer.send_signed_transaction(|_account| {
			
			Call::submit_transaction {
				address: details.address,
				amount: details.address,
				transaction,
			}
		});

		for (acc, res) in &results {
			match res {
				Ok(()) => log::info!("[{:?}] Submitted submit_transaction request", res),
				Err(e) =>
					log::error!("[{:?}] Failed to submit submit_transaction request: {:?}", res, e),
			}
		}

		Ok(())
	}

	pub fn handle_transaction_retry(
		details: WithdrawalRequest<T>,
		btc_config: types::BTCConfig,
	) -> OffchainResult<()> {
		// pick all the known validators
		let validators = CurrentValidators::<T>::get();

		if validators.is_empty() {
			panic!("No BTC validators found!");
		}

		let now = <T as frame_system::Config>::block_number();

		let transaction =
			btc_client::BTCClient::generate_transaction_from_withdrawal_request(details)
				.unwrap()
				.txid()
				.as_ref()
				.to_vec();

		let signer = Signer::<T, T::AuthorityId>::all_accounts();
		if !signer.can_sign() {
			return Err(
				"No local accounts available. Consider adding one via `author_insertKey` RPC.",
			)
		}

		
		let results = signer.send_signed_transaction(|_account| {
			
			Call::submit_transaction {
				address: details.address,
				amount: details.address,
				transaction,
			}
		});

		for (acc, res) in &results {
			match res {
				Ok(()) => log::info!("[{:?}] Submitted submit_transaction request", res),
				Err(e) =>
					log::error!("[{:?}] Failed to submit submit_transaction request: {:?}", res, e),
			}
		}

		Ok(())
	}

	/// Handle a pending BTC transaction for the BTC Pools pallet.
	///
	/// This function processes a pending BTC transaction by signing it with the configured signer's
	/// private key. If the transaction has not been signed yet, the function signs the transaction
	/// and stores the signature. If the threshold for the number of signatures is reached, the
	/// transaction is considered processed and may be broadcast to the BTC chain.
	///
	/// # Parameters
	///
	/// - `hash`: The hash of the pending BTC transaction.
	/// - `details`: Details of the pending BTC transaction, including recipient, amount, and
	///   signatures.
	/// - `btc_config`: BTC configuration parameters.
	///
	/// # Errors
	///
	/// Returns an `OffchainResult` indicating the success or failure of processing the pending BTC
	/// transaction. In case of success, `Ok(())` is returned.
	///
	/// # Remarks
	///
	/// - The function signs the transaction using the signer's private key and stores the
	///   signature.
	/// - If the number of signatures reaches the configured threshold, the transaction is
	///   considered processed, and an event is emitted.
	/// - The `CurrentPoolAddress` and `CurrentPoolThreshold` storages are used to gather necessary
	///   information.
	pub fn handle_transaction_sign(
		details: WithdrawalRequest<T>,
		btc_config: types::BTCConfig,
	) -> OffchainResult<()> {
		let mut key = [0u8; 32];
		key[..32].copy_from_slice(&btc_config.signer_public_key);
		let signer_address = sr25519::Public(key);
		let signer = BTCClientSignature::from(signer_address);

		// if we have not already signed, sign the transaction
		if details.signatures.get(&signer.from.to_vec()).is_none() {
			// let first validate the data to sign
			let transaction = details.get_latest_transaction();
			BTCClient::validate_tx_data_from_transaction_details(transaction)?;

			// generate the data to sign
			let prevouts = Prevouts::All(&transaction.consumed_utxos);
			let wallet_script = BTCClient::generate_taproot_script_with_required_signer(
				CurrentValidators::<T>::get(),
			);
			let sighash_sig = SighashCache::new(&mut transaction.clone())
				.taproot_script_spend_signature_hash(
					0,
					&prevouts,
					ScriptPath::with_defaults(&wallet_script),
					SchnorrSighashType::Default,
				)
				.unwrap();

			// sign transaction using our key
			let signature = signer.sign(&sighash_sig).expect("Signing Failed!!");

			let signer = Signer::<T, T::AuthorityId>::all_accounts();
			if !signer.can_sign() {
				return Err(
					"No local accounts available. Consider adding one via `author_insertKey` RPC.",
				)
			}

			let results = signer.send_signed_transaction(|_account| {
				Call::submit_transaction_signature {
					address: details.address,
					amount: details.amount,
					signature,
				};

				for (acc, res) in &results {
					match res {
						Ok(()) => log::info!(
							"[{:?}] Submitted submit_transaction_signature",
							details.tx_data
						),
						Err(e) => log::error!(
							"[{:?}] Failed to submit submit_transaction_signature: {:?}",
							details.tx_data,
							e
						),
					}
				}
			});
		}

		Ok(())
	}
}

pub fn handle_transaction_broadcast(
	details: WithdrawalRequest<T>,
	btc_config: types::BTCConfig,
) -> OffchainResult<()> {
	// we use a simple round robin to determin if its our turn to submit
	let current_validators = CurrentValidators::<T>::get().iter().len();
	let current_block = <T as frame_system::Config>::block_number();
	// cb = 100, v = 5, 106 => 106%5=1, 107=2
	let selected_validator_index = *current_block % current_validators as u32;
	let selected_validator = current_validators.get(selected_validator_index as usize);

	// the signer does not have a method to read all available public keys, we instead sign
	// a dummy message and read the current pub key from the signature.
	let signer = Signer::<T, T::AuthorityId>::all_accounts();
	if !signer.can_sign() {
		return Err("No local accounts available. Consider adding one via `author_insertKey` RPC.")
	}

	let signature = signer.sign_message(b"test");
	let account: &T::AccountId =
		&signature.first().expect("Unable to retreive signed message").0.id; // the unwrap here is ok since we checked if can_sign() is true above

	if account != &selected_validator {
		log::debug!(
			"handle_transaction_broadcast: Not our turn to broadcast, selected signer is {:?}",
			selected_validator
		);
		return Ok(())
	}

	// its our turn, so setup signatures and broadcast
	let tx_id =
		BTCClient::broadcast_completed_transaction(details.get_latest_transaction().clone());

	// post the transaction to update this data onchain
	let results = signer.send_signed_transaction(|_account| {
		Call::submit_transaction_broadcast_result {
			address: details.address,
			amount: details.amount,
			tx_id,
		};

		for (acc, res) in &results {
			match res {
				Ok(()) =>
					log::info!("[{:?}] Submitted submit_transaction_signature", details.tx_data),
				Err(e) => log::error!(
					"[{:?}] Failed to submit submit_transaction_signature: {:?}",
					details.tx_data,
					e
				),
			}
		}
	});

	Ok(())
}

pub fn handle_transaction_retry(
	details: WithdrawalRequest<T>,
	btc_config: types::BTCConfig,
) -> OffchainResult<()> {
	// analyse the state of the latest transaction
	let tx = details.get_latest_transaction();

	let signer = Signer::<T, T::AuthorityId>::all_accounts();
	if !signer.can_sign() {
		return Err("No local accounts available. Consider adding one via `author_insertKey` RPC.")
	}

	// is the transaction success
	if BTCClient::is_transaction_successful(tx.tx_id) {
		// all good, only thing left to do is to mark the transaction as completed
		// this should remove it from queue and then make way for next item in queue
		let results = signer.send_signed_transaction(|_account| {
			
			Call::submit_transaction_broadcasted_result {
				address: details.recipient,
				amount: details.amount,
			}
		});

		for (acc, res) in &results {
			match res {
				Ok(()) => log::info!("[{:?}] Submitted handle withdraw request", res),
				Err(e) =>
					log::error!("[{:?}] Failed to submit handle withdraw request: {:?}", res, e),
			}
		}

		// completed, exit the function
		return Ok(())
	}

	// if the transaction is timed out, then we mark it to retry
	let current_block = <T as frame_system::Config>::block_number();
	if tx.timeout_block < current_block {
		let results =
			signer.send_signed_transaction(|_account| Call::submit_transaction_for_retry {
				address: details.recipient,
				amount: details.amount,
			});

		for (acc, res) in &results {
			match res {
				Ok(()) => log::info!("[{:?}] Submitted handle withdraw request", res),
				Err(e) =>
					log::error!("[{:?}] Failed to submit handle withdraw request: {:?}", res, e),
			}
		}
	}

	Ok(())
}
