use pallet_evm_precompile_utils::{
	precompile,
	prelude::*,
};
use frame_support::traits::ConstU32;
use sp_core::{H160, H256, U256};
use sp_std::vec::Vec;

#[precompile]
pub struct BosIntentPrecompile<Runtime>(PhantomData<Runtime>);

#[precompile::public("registerIntent(uint256,address,address,bytes)")]
fn register_intent(
	handle: &mut impl PrecompileHandle,
	btc_amount: U256,
	btc_address: H160,
	target_contract: H160,
	encoded_call: UnboundedBytes,
) -> EvmResult<U256> {
	let origin = handle.context().caller;
	let encoded_call: Vec<u8> = encoded_call.into();

	pallet_bos_intent::Pallet::<Runtime>::register_intent(
		origin.into(),
		btc_amount,
		btc_address,
		target_contract,
		encoded_call,
	)
	.map_err(|e| revert(format!("Failed to register intent: {:?}", e)))?;

	let intent_id = pallet_bos_intent::Pallet::<Runtime>::intents_count() - U256::one();
	Ok(intent_id)
}

#[precompile::public("executeIntent(uint256)")]
fn execute_intent(handle: &mut impl PrecompileHandle, intent_id: U256) -> EvmResult<()> {
	let origin = handle.context().caller;

	pallet_bos_intent::Pallet::<Runtime>::execute_intent(origin.into(), intent_id)
		.map_err(|e| revert(format!("Failed to execute intent: {:?}", e)))?;

	Ok(())
}

#[precompile::public("retrieveTx(bytes32)")]
fn retrieve_tx(handle: &mut impl PrecompileHandle, txid: H256) -> EvmResult<UnboundedBytes> {
	let pallet_bos_intent = pallet_bos_intent::Pallet::<Runtime>::retrieve_tx(txid);

	if let Some((block, timestamp, inputs, outputs, encoded_call)) = pallet_bos_intent {
		let mut result = Vec::new();

		// Encode block number
		result.extend_from_slice(&block.to_be_bytes());

		// Encode timestamp
		result.extend_from_slice(&timestamp.to_be_bytes());

		// Encode inputs
		result.extend_from_slice(&(inputs.len() as u32).to_be_bytes());
		for input in inputs {
			result.extend_from_slice(&(input.address.len() as u32).to_be_bytes());
			result.extend_from_slice(&input.address);
			result.extend_from_slice(&input.amount.to_be_bytes());
		}

		// Encode outputs
		result.extend_from_slice(&(outputs.len() as u32).to_be_bytes());
		for output in outputs {
			result.extend_from_slice(&(output.address.len() as u32).to_be_bytes());
			result.extend_from_slice(&output.address);
			result.extend_from_slice(&output.amount.to_be_bytes());
		}

		// Encode encoded_call
		result.extend_from_slice(&(encoded_call.len() as u32).to_be_bytes());
		result.extend_from_slice(&encoded_call);

		Ok(result.into())
	} else {
		Err(revert("Transaction not found"))
	}
}