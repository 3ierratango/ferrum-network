use super::*;
use electrum_client::{Client, ElectrumApi, ListUnspentRes};

pub type SignatureMap = BTreeMap<T::AccountId, Vec<u8>>;

#[derive(
	Clone,
	Eq,
	PartialEq,
	Decode,
	Encode,
	Debug,
	Serialize,
	Deserialize,
	scale_info::TypeInfo,
	Default,
)]
/// Represents the details of a transaction, including its signatures, transaction ID,
/// fees, candidate UTXOs, previous transaction hash, timeout block, and creation block.
pub struct TransactionDetails {
	/// A map of signatures associated with the transaction.
	pub signatures: SignatureMap,

	/// An optional vector representing the transaction ID.
	pub tx_id: Option<Vec<u8>>,

	/// Transaction data to sign
	pub tx_data: Vec<u8>,

	/// The transaction fees associated with the transaction.
	pub fees: u32,

	/// An optional vector containing candidate Unspent Transaction Outputs (UTXOs).
	pub candidate_utxos: Option<Vec<ListUnspentRes>>,

	/// A vector containing candidate Unspent Transaction Outputs (UTXOs) used in the tx_data
	pub consumed_utxos: Option<Vec<ListUnspentRes>>,

	/// An optional vector representing the hash of the previous transaction.
	pub prev_tx_hash: Option<Vec<u8>>,

	/// The block at which the transaction will timeout.
	pub timeout_block: u32,

	/// The block at which the transaction was created.
	pub created_block: u32,
}

/// Represents the status of a withdrawal process.
///
/// This enum defines different stages in the withdrawal lifecycle.
pub enum WithdrawalStatus {
	/// Indicates that a new withdrawal process has been initiated.
	New,

	/// Indicates that the transaction for the withdrawal has been created.
	TransactionCreated,

	/// Indicates that the transaction for the withdrawal has been signed.
	TransactionSigned,

	/// Indicates that the withdrawal is awaiting confirmation.
	AwaitingConfirmation,

	/// Indicates that the transaction has to be recreated and signed
	TransactionRetry,
}

#[derive(
	Clone,
	Eq,
	PartialEq,
	Decode,
	Encode,
	Debug,
	Serialize,
	Deserialize,
	scale_info::TypeInfo,
	Default,
)]
/// Represents a withdrawal request, containing information such as the recipient's address,
/// withdrawal amount, creation timestamp, and a list of associated transaction details.
pub struct WithdrawalRequest<T> {
	/// A vector representing the recipient's address for the withdrawal.
	pub recipient: Vec<u8>,

	/// The withdrawal amount in some units (e.g., tokens, currency).
	pub amount: u32,

	/// The timestamp indicating when the withdrawal request was created.
	pub created_at: u32,

	/// A vector containing detailed information about associated transactions.
	pub transactions: Vec<TransactionDetails>,

	/// Current Status of withdrawal
	pub status: WithdrawalStatus,

	/// extra param for generic type
	pub config: PhantomData<T>,
}

impl<T: Config> WithdrawalRequest<T> {
	fn get_oldest_transaction(&self) -> TransactionDetails {
		let mut oldest_transaction: TransactionDetails = self.transactions.first();
		for tx in self.transactions {
			if tx.created_block < oldest_transaction {
				oldest_transaction = tx
			}
		}
		oldest_transaction
	}

	fn get_latest_transaction(&self) -> TransactionDetails {
		let mut latest_transaction: TransactionDetails = self.transactions.first();
		for tx in self.transactions {
			if tx.created_block > latest_transaction {
				latest_transaction = tx
			}
		}
		latest_transaction
	}

	fn can_create_new_transaction(&self) -> bool {
		// can only add a new transaction if oldest one has timed out
		let tx = self.get_latest_transaction();
		let now = frame_system::Pallet::<T>::now();
		tx.timeout_block < now
	}

	fn insert_new_transaction(
		&mut self,
		tx_data: Vec<u8>,
		fees: u32,
		consumed_utxos: Vec<ListUnspentRes>,
	) -> Result<(), String> {
		// can only add a new transaction if oldest one has timed out
		let tx = self.get_latest_transaction();
		let now = frame_system::Pallet::<T>::now();

		// ensure transaction is in the correct status
		ensure!(
			self.status == TransactionRetry || self.status == New,
			Error::<T>::WrongStateChange
		);

		if tx.timeout_block > now {
			// the old transaction has not timed out, exit
			return Err("Old transaction valid!")
		}

		// sanity check, ensure the old transaction has not been processed
		if Self::check_txid_success(tx.tx_id) {
			// the old transactino succeeded, cannot create new
			return Err("Old transaction succeeded")
		}

		// create a new transaction from last latest one
		let new_transaction = TransactionDetails {
			signatures: Default::default(),
			tx_id: None,
			tx_data,
			fees,
			consumed_utxos,
			candidate_utxos: tx.candidate_utxos,
			prev_tx_hash: tx.hash,
			created_block: now,
			timeout_block: now + T::TransactionExpiryTimeout::get(),
		};

		self.transactions.push(new_transaction);

		// change transaction status
		self.status == TransactionCreated;

		Ok(())
	}

	fn insert_new_signature(
		&mut self,
		signer: T::AccountId,
		signature: Vec<u8>,
	) -> Result<(), String> {
		// always working with the latest transaction only
		let tx = self.get_latest_transaction();
		let now = frame_system::Pallet::<T>::now();

		// ensure transaction is in the correct status
		ensure!(self.status == TransactionCreated, Error::<T>::WrongStateChange);

		if tx.timeout_block > now {
			// the transaction has timed out, exit
			return Err("Old transaction valid!")
		}

		// ensure the signer has not already signed
		if tx.signatures.get(&signer).is_some() {
			return Err(Error::<T>::AlreadySigned)
		}

		tx.signatures.insert(signer, signature);

		// change transaction status if we have enough signatures
		if tx.signatures.len() > CurrentPoolThreshold::<T>::get() {
			self.status == TransactionSigned
		}

		Ok(())
	}

	fn set_tx_id(&mut self, tx_id: Vec<u8>) -> Result<(), String> {
		// always working with the latest transaction only
		let tx = self.get_latest_transaction();
		let now = frame_system::Pallet::<T>::now();

		// ensure transaction is in the correct status
		ensure!(self.status == TransactionSigned, Error::<T>::WrongStateChange);

		tx.tx_id = Some(tx_id);

		self.status == AwaitingConfirmation;

		Ok(())
	}
}
