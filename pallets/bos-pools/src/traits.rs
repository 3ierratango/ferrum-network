use super::*;

/// Trait for handling signatures in the BosPools pallet.
pub trait BosPoolsHandler {
	/// Register a signature in the BosPools pallet.
	///
	/// # Parameters
	///
	/// - `message_hash`: Hash of the message to be signed.
	/// - `signature`: The signature to be registered.
	///
	/// # Returns
	///
	/// Returns `Ok(())` if the registration is successful.
	fn register_signature(message_hash: Vec<u8>, signature: Vec<u8>) -> DispatchResult;
}

impl BosPoolsHandler for crate::Pallet<T> {
	fn register_signature(message_hash: Vec<u8>, signature: Vec<u8>) -> DispatchResult {
		// check if we have a message with the given message hash in our signing queue
		// push the signature to storage
		let _ = PendingTransactions::<T>::try_mutate(
			message_hash.clone(),
			|details| -> Result<(), ()> {
				let mut default = TransactionDetails::default();
				let mut signatures = &mut details.as_mut().unwrap_or(&mut default).signatures;
				signatures.insert(signer_address.to_vec(), signature.0.to_vec());

				Self::deposit_event(Event::TransactionSignatureSubmitted {
					hash: message_hash.clone(),
					signature: signature.0.to_vec(),
				});

				Ok(())
			},
		);
		log::info!(
			"Registered signature for message hash: {:?}, signature: {:?}",
			message_hash,
			signature
		);
		Ok(())
	}
}
