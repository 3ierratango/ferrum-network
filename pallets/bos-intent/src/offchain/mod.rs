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
use electrum_client::{Client, ElectrumApi};
use sp_runtime::traits::Zero;
pub mod types;
use bitcoin::Txid;
use sp_core::sr25519;
pub use types::*;

pub mod btc_client;
pub mod chain_queries;
pub mod chain_utils;
pub mod evm_client;

impl<T: Config> Pallet<T> {
	pub fn execute_tx_scan(block_number: u64, btc_config: types::BTCConfig) -> OffchainResult<()> {
		let current_pool_address = CurrentPoolAddress::<T>::get();

		// get incoming transactions
		let incoming_transactions =
			btc_client::BTCClient::get_incoming_transactions(current_pool_address).unwrap();

		// remove any already processed transactions
		let tx_ids = incoming_transactions.iter().filter(
			|x| !ProcessedTransactions::<T>::get().contains(x)
		).collect();

		// push transactions to evm
		evm_client::handle_new_incoming_transaction(txids);

		// process the incoming transactions
		let txids = Self::record_seen_transactions(txids);

		Ok(())
	}

	pub fn record_seen_transactions(successful: Vec<Vec<u8>>) -> DispatchResult {
		let mut new_tx_ids = vec![];
		// record all tx_ids to pallet storage

		// sign transaction using our key
		let signature = signer.sign(&sighash_sig).expect("Signing Failed!!");

		let signer = Signer::<T, T::AuthorityId>::all_accounts();
		if !signer.can_sign() {
			return Err(
				"No local accounts available. Consider adding one via `author_insertKey` RPC.",
			)
		}

		let results = signer.send_signed_transaction(|_account| {
			Call::ext_record_seen_transactions {
				transactions: successful.clone()
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

		Ok(())
	}
}
