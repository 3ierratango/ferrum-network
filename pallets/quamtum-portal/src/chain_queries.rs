#![cfg_attr(not(feature = "std"), no_std)]

use log::log;
use crate::pallet::*;

use sp_runtime::{
	offchain::{
		http,
		Duration,
	},
	codec::{
		Decode, Encode
	},
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::json;
use sp_runtime::offchain::http::HttpResult;
use sp_std::{collections::vec_deque::VecDeque, prelude::*, str};
use crate::chain_utils::{ChainRequestError, ChainRequestResult, ToJson, JsonSer};
use crate::chain_utils::ChainUtils;
use sp_core::{ H256 };
use ethereum::{LegacyTransaction, TransactionV2};
use ethabi_nostd::ParamKind::Address;
use crate::contract_client::ContractClient;
use crate::qp_types::{QpLocalBlock, QpRemoteBlock, QpTransaction};
use crate::quantum_portal_client::QuantumPortalClient;

const FETCH_TIMEOUT_PERIOD: u64 = 30000; // in milli-seconds
const DUMMY_HASH: H256 = H256::zero();
const ZERO_HASH: H256 = H256::zero();

pub fn de_string_list_to_bytes_list<'de, D>(de: D) -> Result<Vec<Vec<u8>>, D::Error>
	where
		D: Deserializer<'de>,
{
	let s: Vec<&str> = Deserialize::deserialize(de)?;
	let list = s.iter().map(|v| v.as_bytes().to_vec()).collect();
	Ok(list)
}

pub fn de_string_to_bytes<'de, D>(de: D) -> Result<Vec<u8>, D::Error>
	where
		D: Deserializer<'de>,
{
	let s: &str = Deserialize::deserialize(de)?;
	Ok(s.as_bytes().to_vec())
}

// curl --data
// '{"method":"eth_chainId","params":[],"id":1,"jsonrpc":"2.0"}' -H "Content-Type: application/json"
// -X POST localhost:8545
#[derive(Debug, Deserialize, Serialize, Encode, Decode)]
pub struct JsonRpcRequest {
	pub id: u32,
	#[serde(deserialize_with = "de_string_to_bytes")]
	pub method: Vec<u8>,
	#[serde(deserialize_with = "de_string_list_to_bytes_list")]
	pub params: Vec<Vec<u8>>,
}

#[derive(Deserialize, Encode, Decode)]
pub struct  JsonRpcResponse<T> {
	pub id: u32,
	#[serde(deserialize_with = "de_string_to_bytes")]
	pub jsonrpc: Vec<u8>,
	pub response: T,
}

#[derive(Debug, Deserialize)]
pub struct CallResponse {
	#[serde(deserialize_with = "de_string_to_bytes")]
	pub result: Vec<u8>,
}

impl ToJson for TransactionV2 {
	type BaseType = TransactionV2;
	fn to_json(&self) -> Vec<u8> {
		let mut j = JsonSer::new();
		let j = match self {
			TransactionV2::Legacy(tx) =>
				j
					.start()
					.string("nonce",
							str::from_utf8(ChainUtils::u256_to_hex_0x(&tx.nonce).as_slice()).unwrap())
					.string("gas_price",
							str::from_utf8(ChainUtils::u256_to_hex_0x(&tx.gas_price).as_slice()).unwrap())
					.string("gas_limit",
							str::from_utf8(ChainUtils::u256_to_hex_0x(&tx.gas_limit).as_slice()).unwrap())
					// .string("action",
					// 		str::from_utf8(ChainUtils::u256_to_hex_0x(&tx.action).as_slice()).unwrap())
					.string("value",
							str::from_utf8(ChainUtils::u256_to_hex_0x(&tx.value).as_slice()).unwrap())
					.string("input", str::from_utf8(&tx.input).unwrap())
					.val("signature",
						str::from_utf8(
						JsonSer::new()
							.start()
							.string("r", str::from_utf8(ChainUtils::h256_to_hex_0x(tx.signature.r()).as_slice()).unwrap())
							.string("s", str::from_utf8(ChainUtils::h256_to_hex_0x(tx.signature.s()).as_slice()).unwrap())
							.num("v", tx.signature.v())
							.end()
							.to_vec().as_slice()
						).unwrap()
					)
					.end()
					.to_vec()
			,
			TransactionV2::EIP1559(tx) => Vec::new(),
			TransactionV2::EIP2930(tx) => Vec::new()
		};
		Vec::from(j)
	}
}

fn fetch_json_rpc_body(
	base_url: &str,
	req: &JsonRpcRequest,
) -> Result<Vec<u8>, ChainRequestError> {
	let mut params = JsonSer::new();
	(&req.params).into_iter().for_each(|p| {
		params.arr_val(str::from_utf8(p.as_slice()).unwrap());
		()
	});
	let mut json_req = JsonSer::new();
	let json_req_s = json_req
		.start()
		.num("id", req.id as u64)
		.string("method", str::from_utf8(&req.method).unwrap())
		.string("jsonrpc", "2.0")
		.arr("params",
			str::from_utf8(params.to_vec().as_slice()).unwrap()
		)
		.end()
		.to_vec();
	let json_req_str = str::from_utf8(&json_req_s).unwrap();
	log::info!("About to submit {}", json_req_str);
	let request: http::Request<Vec<&[u8]>> = http::Request::post(base_url,
	 Vec::from([json_req_s.as_slice()]));
	let timeout = sp_io::offchain::timestamp()
		.add(Duration::from_millis(FETCH_TIMEOUT_PERIOD));

	let pending = request
		// .deadline(timeout) // Setting the timeout time
		.add_header("Content-Type", "application/json")
		.send() // Sending the request out by the host
		.map_err(|e| {
			log::info!("An ERROR HAPPNED!");
			// println!("ERRROOOORRRR {:?}", e);
			log::error!("{:?}", e);
			ChainRequestError::ErrorGettingJsonRpcResponse
		})?;

	log::info!("Pendool!");
	// println!("Pendool!");
	// By default, the http request is async from the runtime perspective. So we are asking the
	//   runtime to wait here
	// The returning value here is a `Result` of `Result`, so we are unwrapping it twice by two `?`
	//   ref: https://docs.substrate.io/rustdocs/latest/sp_runtime/offchain/http/struct.PendingRequest.html#method.try_wait
	let response_a = pending.try_wait(timeout);
	// let response_0 = pending.wait();
	let response_0 = match response_a {
		Ok(r) => {
			// println!("Result got");
			log::info!("Result got");
			Ok(r)
		},
		Err(e) => {
			// println!("ERRROOOORRRR AFDTER {:?}", e);
			log::info!("An ERROR HAPPNED!");
			log::info!("An ERROR HAPPNED UYPOOOOOOOOOOO ! {:?}", e);
			Err(ChainRequestError::ErrorGettingJsonRpcResponse)
		},
	}?;
	let response = match response_0 {
		Ok(r) => {
			log::info!("Result got 2");
			Ok(r)
		},
		Err(e) => {
			log::info!("An ERROR HAPPNED 2!");
			log::info!("An ERROR HAPPNED UYPOOOOOOOOOOO 2 ! {:?}", e);
			Err(ChainRequestError::ErrorGettingJsonRpcResponse)
		}
	}?;
	// let response = pending
	// 	.try_wait(timeout)
	// 	.map_err(|e| {
	// 		log::info!("An ERROR HAPPNED!");
	// 		log::info!("An ERROR HAPPNED UYPOOOOOOOOOOO ! {:?}", e);
	// 		log::error!("{:?}", e);
	// 		ChainRequestError::ErrorGettingJsonRpcResponse
	// 	})?
	// 	.map_err(|e| {
	// 		log::info!("An ERROR HAPPNED22!");
	// 		log::error!("{:?}", e);
	// 		ChainRequestError::ErrorGettingJsonRpcResponse
	// 	})?;

	log::info!("Response is ready!");
	let body = response.body().collect::<Vec<u8>>().clone();
	log::info!("Response code got : {}-{}", &response.code, str::from_utf8(&body.as_slice()).unwrap());

	if response.code != 200 {
		log::error!("Unexpected http request status code: {}", response.code);
		return Err(ChainRequestError::ErrorGettingJsonRpcResponse)
	}

	Ok(body)
}

pub fn fetch_json_rpc<T>(
	base_url: &str,
	req: &JsonRpcRequest,
) -> Result<Box<T>, ChainRequestError>
where T: for<'de> Deserialize<'de> {
	// println!("fetchin {} : {:?}", base_url, req);
	let body = fetch_json_rpc_body(base_url, req)?;
	// println!("Response body got : {}", str::from_utf8(&body).unwrap());
	log::info!("Response body got : {}", str::from_utf8(&body).unwrap());
	let rv: serde_json::Result<T> = serde_json::from_slice(&body);
	match rv {
		Err(err) => {
			log::error!("Error while parsing json {:?}", err);
			Err(ChainRequestError::ErrorGettingJsonRpcResponse)
		},
		Ok(v) => Ok(Box::new(v)),
	}
}

#[derive(Debug, Deserialize, Encode, Decode)]
struct GetChainIdResponse {
	#[serde(deserialize_with = "de_string_to_bytes")]
	result: Vec<u8>,
}

pub struct ChainQueries/*<T: Config>*/ {
}

impl ChainQueries {
// impl<T: Config> ChainQueries<T> {
	pub fn chain_id(url: &str) -> Result<u32, ChainRequestError> {
		log::info!("About to get chain_id {}", url);
		let req = JsonRpcRequest {
			id: 1,
			params: Vec::new(),
			method: b"eth_chainId".to_vec(),
		};
		log::info!("Have request {:?}", &req);
		let res: Box<GetChainIdResponse> = fetch_json_rpc(url, &req)?;
		log::info!("Result is {:?}", &res);
		let chain_id = ChainUtils::hex_to_u64(&res.result)?;
		Ok(chain_id as u32)
	}
}

pub struct QuantumPortalContract;

impl QuantumPortalContract {
	pub fn create_finalize_transaction(
		chain_id: u64,
		blockNonce: u64,
		finalizer_hash: H256,
		finalizers: &[H256],
	) -> ChainRequestResult<TransactionV2> {
		// TODO: We need to encode the method. 'ethabi-nostd' cannot be imported
		// because of sp_std, so here are the alternatives:
		// - Manually construct the function call as [u8].
		// function finalize(
		// 	uint256 remoteChainId,
		// 	uint256 blockNonce,
		// 	bytes32 finalizersHash,
		// 	address[] memory finalizers
		// ) ...
		// The last item is a bit complicated, but for now we pass an empty array.
		// Support buytes and dynamic arrays in future
		Err(ChainRequestError::ErrorCreatingTransaction)
	}

	pub fn create_mine_transaction(
		chain1: u64,
		block_nonce: u64,
		txs: &[QpTransaction],
	) -> ChainRequestResult<TransactionV2> {
		Err(ChainRequestError::ErrorCreatingTransaction)
	}

	pub fn is_local_block_ready(
		chain_id: u64,
	) -> ChainRequestResult<bool> {
		Err(ChainRequestError::ErrorCreatingTransaction)
	}

	pub fn last_local_block(
		chain_id: u64,
	) -> ChainRequestResult<QpLocalBlock> {
		Err(ChainRequestError::ErrorCreatingTransaction)
	}

	pub fn mined_block_by_nonce(
		chain_id: u64,
		nonce: u64,
	) -> ChainRequestResult<(QpRemoteBlock, Vec<QpTransaction>)> {
		Err(ChainRequestError::ErrorCreatingTransaction)
	}

	pub fn local_block_by_nonce(
		chain_id: u64,
		nonce: u64,
	) -> ChainRequestResult<(QpLocalBlock, Vec<QpTransaction>)> {
		Err(ChainRequestError::ErrorCreatingTransaction)
	}

	pub fn last_finalized_block(
		chain_id: u64,
	) -> ChainRequestResult<QpLocalBlock> {
		Err(ChainRequestError::ErrorCreatingTransaction)
	}
}

pub struct QuantumPortalRunner {
}

impl QuantumPortalRunner {
	pub fn client() -> QuantumPortalClient {
		let lgr_mgr = ChainUtils::hex_to_address(
			b"d36312d594852462d6760042e779164eb97301cd");
		let contract = ContractClient::new(
			"", &lgr_mgr, 4);
		QuantumPortalClient::new(contract)
	}

	pub fn finalize(
		chain_id: u64,) -> ChainRequestResult<()>{
		let c = Self::client();
		let block = c.last_remote_mined_block(chain_id)?;
		let last_fin = QuantumPortalContract::last_finalized_block(chain_id)?;
		if block.nonce > last_fin.nonce {
			log::info!("Calling mgr.finalize({}, {})", chain_id, last_fin.nonce);
			QuantumPortalContract::create_finalize_transaction(
				chain_id, block.nonce, DUMMY_HASH, &[])?;
		} else {
			log::info!("Nothing to finalize for ({})", chain_id);
		}
		Ok(())
	}

	pub fn mine(
		chain1: u64,
		chain2: u64,
	) -> ChainRequestResult<bool> {
		let c = Self::client();
		let block_ready = c.is_local_block_ready(chain2)?;
		if !block_ready { return  Ok(false); }
		let last_block = QuantumPortalContract::last_local_block(chain2)?;
		let last_mined_block = c.last_remote_mined_block(chain1)?;
		log::info!("Local block (chain {}) nonce is {}. Remote mined block (chain {}) is {}",
			chain1, last_block.nonce, chain2, last_mined_block.nonce);
		if last_mined_block.nonce >= last_block.nonce {
			log::info!("Nothing to mine!");
			return Ok(false);
		}
		log::info!("Last block is on chain1 for target {} is {}", chain2, last_block.nonce);
		let mined_block = QuantumPortalContract::mined_block_by_nonce(chain1, last_block.nonce)?;
		let already_mined = !mined_block.0.block_hash.eq(&ZERO_HASH);
		if already_mined {
			return Err(ChainRequestError::RemoteBlockAlreadyMined);
		}
		let source_block = QuantumPortalContract::local_block_by_nonce(chain2, last_block.nonce)?;
		let txs = source_block.1;
		log::info!("About to mine block {}:{}", chain1, source_block.0.nonce);
		QuantumPortalContract::create_mine_transaction(chain1, source_block.0.nonce, &txs)?;
		// TODO: Store and monitor the mine transaction.
		// If
		Ok(true)
	}
}
