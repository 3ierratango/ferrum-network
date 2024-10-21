#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Decode, Encode};
use frame_support::{
	dispatch::DispatchResult,
	pallet_prelude::*,
	traits::Currency,
};
use frame_system::pallet_prelude::*;
use sp_core::{H160, H256, U256};
use sp_std::prelude::*;

pub use pallet::*;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;

pub mod weights;
pub use weights::*;

#[frame_support::pallet]
pub mod pallet {
	use super::*;

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	#[pallet::config]
	pub trait Config: frame_system::Config {
		type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
		type Currency: Currency<Self::AccountId>;
		type WeightInfo: WeightInfo;
	}

	#[pallet::storage]
	#[pallet::getter(fn intents)]
	pub type Intents<T: Config> = StorageMap<_, Blake2_128Concat, U256, Intent<T::AccountId>>;

	#[pallet::storage]
	#[pallet::getter(fn intents_count)]
	pub type IntentsCount<T: Config> = StorageValue<_, U256, ValueQuery>;

	#[pallet::storage]
	#[pallet::getter(fn bitcoin_transactions)]
	pub type BitcoinTransactions<T: Config> = StorageMap<_, Twox64Concat, H256, BitcoinTransaction>;

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		IntentRegistered {
			id: U256,
			btc_amount: U256,
			btc_address: H160,
			target_contract: H160,
			encoded_call: Vec<u8>,
		},
		IntentExecuted {
			id: U256,
		},
	}

	#[pallet::error]
	pub enum Error<T> {
		IntentNotFound,
		IntentAlreadyExecuted,
		ExecutionFailed,
	}

	#[derive(Clone, Encode, Decode, Eq, PartialEq, RuntimeDebug, Default, TypeInfo)]
	pub struct Intent<AccountId> {
		pub btc_amount: U256,
		pub btc_address: H160,
		pub target_contract: H160,
		pub encoded_call: Vec<u8>,
		pub executed: bool,
		pub beneficiary: AccountId,
	}

	#[derive(Clone, Encode, Decode, Eq, PartialEq, RuntimeDebug, TypeInfo)]
	pub struct BitcoinTransaction {
		pub block: u64,
		pub timestamp: u64,
		pub inputs: Vec<TransferItem>,
		pub outputs: Vec<TransferItem>,
		pub encoded_call: Vec<u8>,
	}

	#[derive(Clone, Encode, Decode, Eq, PartialEq, RuntimeDebug, TypeInfo)]
	pub struct TransferItem {
		pub address: Vec<u8>,
		pub amount: u64,
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		#[pallet::call_index(0)]
		#[pallet::weight(T::WeightInfo::register_intent())]
		pub fn register_intent(
			origin: OriginFor<T>,
			btc_amount: U256,
			btc_address: H160,
			target_contract: H160,
			encoded_call: Vec<u8>,
		) -> DispatchResult {
			let who = ensure_signed(origin)?;

			let id = Self::intents_count();
			let intent = Intent {
				btc_amount,
				btc_address,
				target_contract,
				encoded_call: encoded_call.clone(),
				executed: false,
				beneficiary: who,
			};

			<Intents<T>>::insert(id, intent);
			<IntentsCount<T>>::put(id + U256::one());

			Self::deposit_event(Event::IntentRegistered {
				id,
				btc_amount,
				btc_address,
				target_contract,
				encoded_call,
			});

			Ok(())
		}

		#[pallet::call_index(1)]
		#[pallet::weight(T::WeightInfo::execute_intent())]
		pub fn execute_intent(origin: OriginFor<T>, intent_id: U256) -> DispatchResult {
			ensure_root(origin)?;

			let mut intent = Self::intents(intent_id).ok_or(Error::<T>::IntentNotFound)?;
			ensure!(!intent.executed, Error::<T>::IntentAlreadyExecuted);

			// TODO: Implement the actual execution logic here
			// This might involve interacting with other pallets or external systems

			intent.executed = true;
			<Intents<T>>::insert(intent_id, intent);

			Self::deposit_event(Event::IntentExecuted { id: intent_id });

			Ok(())
		}
	}
}

impl<T: Config> Pallet<T> {
	pub fn retrieve_tx(txid: H256) -> Option<(u64, u64, Vec<TransferItem>, Vec<TransferItem>, Vec<u8>)> {
		if let Some(tx) = Self::bitcoin_transactions(txid) {
			Some((
				tx.block,
				tx.timestamp,
				tx.inputs,
				tx.outputs,
				tx.encoded_call,
			))
		} else {
			None
		}
	}
}