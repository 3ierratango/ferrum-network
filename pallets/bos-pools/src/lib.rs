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
#![cfg_attr(not(feature = "std"), no_std)]

/// Edit this file to define custom logic or remove it if it is not needed.
/// Learn more about FRAME and the core library of Substrate FRAME pallets:
/// <https://docs.substrate.io/reference/frame-pallets/>
pub use pallet::*;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;
pub mod weights;
use codec::{Decode, Encode};
use ferrum_primitives::{BTC_OFFCHAIN_SIGNER_CONFIG_KEY, BTC_OFFCHAIN_SIGNER_CONFIG_PREFIX};
use serde::{Deserialize, Serialize};
use sp_runtime::offchain::{
	storage::StorageValueRef,
	storage_lock::{StorageLock, Time},
};
// pub mod traits;
pub mod types;
use sp_std::collections::btree_map::BTreeMap;
pub use weights::*;
pub mod offchain;
use offchain::types::BTCConfig;

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;
	use scale_info::prelude::{vec, vec::Vec};

	#[pallet::pallet]
	#[pallet::without_storage_info]
	pub struct Pallet<T>(_);

	/// Configure the pallet by specifying the parameters and types on which it depends.
	#[pallet::config]
	pub trait Config: frame_system::Config {
		/// Because this pallet emits events, it depends on the runtime's definition of an event.
		type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
		/// The identifier type for an offchain worker.
		type AuthorityId: AppCrypto<Self::Public, Self::Signature>;

		type TransactionExpiryTimeout: Get<Self::BlockNumber>;
		/// Type representing the weight of this pallet
		type WeightInfo: WeightInfo;
	}

	// The pallet's runtime storage items.
	// https://docs.substrate.io/main-docs/build/runtime-storage/
	#[pallet::storage]
	#[pallet::getter(fn current_pool_address)]
	pub type CurrentPoolAddress<T> = StorageValue<_, Vec<u8>, ValueQuery>;

	#[pallet::type_value]
	pub fn DefaultThreshold<T: Config>() -> u32 {
		2u32
	}

	#[pallet::storage]
	#[pallet::getter(fn current_pool_threshold)]
	pub type CurrentPoolThreshold<T> = StorageValue<_, u32, ValueQuery, DefaultThreshold<T>>;

	/// Current pending withdrawals
	#[pallet::storage]
	#[pallet::getter(fn pending_withdrawals)]
	pub type PendingWithdrawals<T> = StorageMap<_, Blake2_128Concat, Vec<u8>, u32>;

	/// Current completed withdrawals
	#[pallet::storage]
	#[pallet::getter(fn pending_withdrawals)]
	pub type CompletedWithdrawals<T> = StorageMap<_, Blake2_128Concat, Vec<u8>, u32>;

	#[pallet::storage]
	#[pallet::getter(fn registered_validators)]
	pub type RegisteredValidators<T> =
		StorageMap<_, Blake2_128Concat, <T as frame_system::Config>::AccountId, Vec<u8>>;

	#[pallet::storage]
	#[pallet::getter(fn current_validators)]
	pub type CurrentValidators<T> =
		StorageValue<_, Vec<<T as frame_system::Config>::AccountId>, ValueQuery>;

	#[pallet::storage]
	#[pallet::getter(fn next_validators)]
	pub type NextValidators<T> =
		StorageValue<_, Vec<<T as frame_system::Config>::AccountId>, ValueQuery>;

	#[pallet::storage]
	#[pallet::getter(fn next_pool_address)]
	pub type NextPoolAddress<T> = StorageValue<_, Vec<u8>, ValueQuery>;

	#[pallet::storage]
	#[pallet::getter(fn admin_role)]
	pub type AdminRole<T: Config> = StorageValue<_, T::AccountId, ValueQuery>;

	#[pallet::storage]
	#[pallet::getter(fn is_pallet_paused)]
	pub type IsPalletPaused<T> = StorageValue<_, bool, ValueQuery>;

	#[pallet::storage]
	#[pallet::getter(fn current_pool_threshold)]
	pub type NextPoolThreshold<T> = StorageValue<_, u32, ValueQuery, DefaultThreshold<T>>;

	/// Current pending withdrawals
	#[pallet::storage]
	#[pallet::getter(fn pending_withdrawals)]
	pub type EmergencyPendingWithdrawals<T> = StorageMap<_, Blake2_128Concat, Vec<u8>, u32>;

	#[pallet::storage]
	#[pallet::getter(fn registered_validators)]
	pub type NextRegisteredValidators<T> =
		StorageMap<_, Blake2_128Concat, <T as frame_system::Config>::AccountId, Vec<u8>>;

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		WithdrawalSubmitted { address: Vec<u8>, amount: u32 },
		TransactionSubmitted { address: Vec<u8>, amount: u32, hash: Vec<u8> },
		TransactionSignatureSubmitted { hash: Vec<u8>, signature: Vec<u8> },
		TransactionProcessed { hash: Vec<u8> },
	}

	// Errors inform users that something went wrong.
	#[pallet::error]
	pub enum Error<T> {
		/// Error names should be descriptive.
		NoneValue,
		/// Errors should have helpful documentation associated with them.
		StorageOverflow,
		RequiresNextTresholdKey,
	}

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
		fn offchain_worker(block_number: BlockNumberFor<T>) {
			log::info!("BTCPools OffchainWorker : Start Execution");
			log::info!("Reading configuration from storage");

			let mut lock = StorageLock::<Time>::new(BTC_OFFCHAIN_SIGNER_CONFIG_PREFIX);
			if let Ok(_guard) = lock.try_lock() {
				let network_config = StorageValueRef::persistent(BTC_OFFCHAIN_SIGNER_CONFIG_KEY);

				let decoded_config = network_config.get::<BTCConfig>();
				log::info!("BTC Pools : Decoded config is {:?}", decoded_config);

				if let Err(_e) = decoded_config {
					log::info!("Error reading configuration, exiting offchain worker");
					return
				}

				if let Ok(None) = decoded_config {
					log::info!("Configuration not found, exiting offchain worker");
					return
				}

				if let Ok(Some(config)) = decoded_config {
					let now = block_number.try_into().map_or(0_u64, |f| f);
					log::info!("Current block: {:?}", block_number);
					if let Err(e) = Self::execute_btc_pools_offchain_worker(now, config) {
						log::warn!(
                            "BTC Pools : Offchain worker failed to execute at block {:?} with error : {:?}",
                            now,
                            e,
                        )
					}
				}
			}

			log::info!("BTC Pools : OffchainWorker : End Execution");
		}
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		#[pallet::call_index(0)]
		#[pallet::weight(T::WeightInfo::do_something())]
		pub fn submit_withdrawal_request(
			origin: OriginFor<T>,
			address: Vec<u8>,
			amount: u32,
		) -> DispatchResult {
			// TODO : Ensure the caller is allowed to submit withdrawals
			let _who = ensure_signed(origin)?;

			// Update storage.
			<PendingWithdrawals<T>>::insert(address.clone(), amount);

			// Emit an event.
			Self::deposit_event(Event::WithdrawalSubmitted { address, amount });
			// Return a successful DispatchResultWithPostInfo
			Ok(())
		}

		#[pallet::call_index(1)]
		#[pallet::weight(T::WeightInfo::do_something())]
		pub fn submit_transaction(
			origin: OriginFor<T>,
			address: Vec<u8>,
			amount: u32,
			transaction: TransactionDetails,
		) -> DispatchResult {
			// TODO : Ensure the caller is allowed to submit withdrawals
			let who = ensure_signed(origin)?;
			let validators = CurrentValidators::<T>::get();
			ensure!(validators.contains(who), Error::<T>::NoPermission);

			PendingWithdrawals::<T>::try_mutate(
				address.clone(),
				amount,
				|withdrawal| -> DispatchResult {
					withdrawal.insert_new_transaction(transaction).unwrap();
					Ok(())
				},
			);

			// Emit an event.
			Self::deposit_event(Event::TransactionSubmitted { address, amount, transaction });
			Ok(())
		}

		#[pallet::call_index(2)]
		#[pallet::weight(T::WeightInfo::do_something())]
		pub fn submit_transaction_signature(
			origin: OriginFor<T>,
			address: Vec<u8>,
			amount: u32,
			signature: Vec<u8>,
		) -> DispatchResult {
			// Ensure the caller is allowed to submit signatures
			let who = ensure_signed(origin)?;
			let validators = CurrentValidators::<T>::get();
			ensure!(validators.contains(who), Error::<T>::NoPermission);

			PendingWithdrawals::<T>::try_mutate(
				address.clone(),
				amount,
				|withdrawal| -> DispatchResult {
					withdrawal.insert_new_signature(who, signature).unwrap();
					Ok(());
				},
			);

			Ok(())
		}

		#[pallet::call_index(7)]
		#[pallet::weight(T::WeightInfo::do_something())]
		pub fn submit_transaction_broadcast_result(
			origin: OriginFor<T>,
			address: Vec<u8>,
			amount: u32,
			tx_id: Vec<u8>,
		) -> DispatchResult {
			// Ensure the caller is allowed to submit signatures
			let who = ensure_signed(origin)?;
			let validators = CurrentValidators::<T>::get();
			ensure!(validators.contains(who), Error::<T>::NoPermission);

			// basic sanity check
			ensure!(!tx_id.is_empty(), Error::<T>::InvalidSubmission);

			PendingWithdrawals::<T>::try_mutate(
				address.clone(),
				amount,
				|withdrawal| -> DispatchResult {
					withdrawal.set_tx_id(tx_id).unwrap();
					Ok(());
				},
			);

			Ok(())
		}

		#[pallet::call_index(8)]
		#[pallet::weight(T::WeightInfo::do_something())]
		pub fn submit_transaction_broadcasted_result(
			origin: OriginFor<T>,
			address: Vec<u8>,
			amount: u32,
		) -> DispatchResult {
			// Ensure the caller is allowed to submit signatures
			let who = ensure_signed(origin)?;
			let validators = CurrentValidators::<T>::get();
			ensure!(validators.contains(who), Error::<T>::NoPermission);

			let withdrawal = PendingWithdrawals::<T>::take(address.clone(), amount);

			// TODO : this storage can be avoided, just add events
			// TODO : Make every extrinsic to have an event
			CompletedWithdrawals::<T>::insert((address.clone(), amount), withdrawal)
		
			Ok(())
		}

		#[pallet::call_index(9)]
		#[pallet::weight(T::WeightInfo::do_something())]
		pub fn submit_transaction_for_retry(
			origin: OriginFor<T>,
			address: Vec<u8>,
			amount: u32,
		) -> DispatchResult {
			// Ensure the caller is allowed to submit signatures
			let who = ensure_signed(origin)?;
			let validators = CurrentValidators::<T>::get();
			ensure!(validators.contains(who), Error::<T>::NoPermission);

			PendingWithdrawals::<T>::try_mutate(
				address.clone(),
				amount,
				|withdrawal| -> DispatchResult {
					// TODO : recheck if timeout actually exceeded
					withdrawal.status = TransactionRetry;
					Ok(());
				},
			);

			Ok(())
		}

		#[pallet::call_index(3)]
		#[pallet::weight(T::WeightInfo::do_something())]
		pub fn register_validator(origin: OriginFor<T>, btc_address: Vec<u8>) -> DispatchResult {
			// TODO : Ensure the caller is allowed to submit withdrawals
			let who = ensure_signed(origin)?;

			RegisteredValidators::<T>::insert(who, btc_address);

			Ok(())
		}

		#[pallet::call_index(4)]
		#[pallet::weight(T::WeightInfo::do_something())]
		pub fn set_current_pool_address(origin: OriginFor<T>, pub_key: Vec<u8>) -> DispatchResult {
			// TODO : Ensure the caller is allowed to submit withdrawals
			let who = ensure_signed(origin)?;

			CurrentPoolAddress::<T>::set(pub_key);

			Ok(())
		}

		#[pallet::call_index(5)]
		#[pallet::weight(0)]
		pub fn set_admin_role(origin: OriginFor<T>, admin_account: T::AccountId) -> DispatchResult {
			// TODO : Ensure this is through democracy/sudo only
			let who = ensure_signed(origin)?;
			AdminRole::<T>::set(Some(admin_account));
			Ok(())
		}

		#[pallet::call_index(6)]
		#[pallet::weight(0)]
		pub fn pause_worker(origin: OriginFor<T>, is_paused: bool) -> DispatchResult {
			// TODO : Ensure this is through democracy/sudo only
			let who = ensure_signed(origin)?;
			IsPalletPaused::<T>::set(is_paused);
			Ok(())
		}

		#[pallet::call_index(7)]
		#[pallet::weight(T::WeightInfo::do_something())]
		pub fn generate_new_pool_address(origin: OriginFor<T>) -> DispatchResult {
			let who = ensure_signed(origin)?;
			// pause this pallet
			IsPalletPaused::<T>::set(true);

			// check for new key in bos validators pallet
			// TODO : Interface via trait
			// let next_threshold_validator_pub_key =
			// 	<pallet_threshold_validators::Pallet<T>>::NextPubKey::<T>::get()
			// 		.ok_or(Error::<T>::RequiresNextTresholdKey);

			let validators = RegisteredValidators::<T>::iter().collect::<Vec<_>>();

			let mut pool_signers = vec![];
			pool_signers.push(next_threshold_validator_pub_key);
			pool_signers.push(validators);
			let new_pool_address = BTCClient::generate_pool_address_from_signers(pool_signers);

			NextPoolAddress::<T>::set(new_pool_address);

			Ok(())
		}

		#[pallet::call_index(8)]
		#[pallet::weight(T::WeightInfo::do_something())]
		pub fn switch_new_pool_address(origin: OriginFor<T>) -> DispatchResult {
			let who = ensure_signed(origin)?;
			// pause this pallet
			IsPalletPaused::<T>::set(true);

			let next_pool_address =
				NextPoolAddress::<T>::get().ok_or(Error::<T>::RequiresNextPoolAddress);

			CurrentPoolAddress::<T>::set(next_pool_address);
			NextPoolAddress::<T>::clear();

			Ok(())
		}
	}
}
