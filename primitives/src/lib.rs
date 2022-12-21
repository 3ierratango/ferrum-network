// Copyright 2019-2022 PureStake Inc.
// This file is part of Moonbeam.

// Moonbeam is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Moonbeam is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Moonbeam.  If not, see <http://www.gnu.org/licenses/>.

//! The Ethereum Signature implementation.
//!
//! It includes the Verify and IdentifyAccount traits for the AccountId20

#![cfg_attr(not(feature = "std"), no_std)]

use parity_scale_codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use sha3::{Digest, Keccak256};
use sp_core::{ecdsa, H160, H256};
use sp_core::offchain::KeyTypeId;

#[cfg(feature = "std")]
pub use serde::{de::DeserializeOwned, Deserialize, Serialize};

/// Defines application identifier for crypto keys for the offchain signer
///
/// When an offchain worker is signing transactions it's going to request keys from type
/// `KeyTypeId` via the keystore to sign the transaction.
/// The keys can be inserted manually via RPC (see `author_insertKey`).
pub const OFFCHAIN_SIGNER_KEY_TYPE: KeyTypeId = KeyTypeId(*b"ofsg");

/// Based on the above `KeyTypeId` we need to generate a pallet-specific crypto type wrapper.
/// We can utilize the supported crypto kinds (`sr25519`, `ed25519` and `ecdsa`) and augment
/// them with the pallet-specific identifier.
pub mod crypto {
    use sp_core::ecdsa::Signature as EcdsaSignagure;
    use sp_core::H256;
    use sp_runtime::MultiSigner::Ecdsa;
    use sp_runtime::{
        app_crypto::{app_crypto, ecdsa},
        traits::Verify,
        MultiSignature, MultiSigner,
    };
	use super::*;

	use sp_core::offchain::KeyTypeId;
    use sp_std::prelude::*;
    use sp_std::str;
	use sp_io::crypto;

    app_crypto!(ecdsa, crate::OFFCHAIN_SIGNER_KEY_TYPE);

	pub fn sign_transaction_hash(
		key_pair: &ecdsa::Public,
		hash: &H256,
	) -> Result<Vec<u8>, ()> {
		let sig: ecdsa::Signature =
			crypto::ecdsa_sign_prehashed(OFFCHAIN_SIGNER_KEY_TYPE, key_pair, &hash.0).unwrap();
		let sig_bytes: &[u8] = &sig.0;
		Ok(Vec::from(sig_bytes))
	}

    /// Identity for the offchain signer key
    pub type AuthorityId = Public;

    /// Signature associated with the offchain signer ecdsa key
    pub type AuthoritySignature = Signature;

    impl frame_system::offchain::AppCrypto<MultiSigner, MultiSignature> for AuthorityId {
        type RuntimeAppPublic = Public;
        type GenericSignature = sp_core::ecdsa::Signature; // sr25519::Signature;
        type GenericPublic = sp_core::ecdsa::Public;

        fn sign(payload: &[u8], public: MultiSigner) -> Option<MultiSignature> {
            let ecdsa_pub = match public {
                Ecdsa(p) => p,
                _ => panic!("Wrong public type"),
            };
            let hash = H256::from_slice(payload); // ChainUtils::keccack(payload);
            let sig = sign_transaction_hash(&ecdsa_pub, &hash).unwrap();

            let mut buf: [u8; 65] = [0; 65];
            buf.copy_from_slice(sig.as_slice());
            let signature = ecdsa::Signature(buf);
            Some(MultiSignature::Ecdsa(signature))
        }
    }

	impl frame_system::offchain::AppCrypto<EthereumSigner, EthereumSignature> for AuthorityId {
        type RuntimeAppPublic = Public;
        type GenericSignature = sp_core::ecdsa::Signature; // sr25519::Signature;
        type GenericPublic = sp_core::ecdsa::Public;

        fn sign(payload: &[u8], public: MultiSigner) -> Option<MultiSignature> {
            let ecdsa_pub = match public {
                Ecdsa(p) => p,
                _ => panic!("Wrong public type"),
            };
            let hash = H256::from_slice(payload); // ChainUtils::keccack(payload);
            let sig = sign_transaction_hash(&ecdsa_pub, &hash).unwrap();

            let mut buf: [u8; 65] = [0; 65];
            buf.copy_from_slice(sig.as_slice());
            let signature = ecdsa::Signature(buf);
            Some(MultiSignature::Ecdsa(signature))
        }
    }

    // implemented for mock runtime in test
    impl frame_system::offchain::AppCrypto<<EcdsaSignagure as Verify>::Signer, EcdsaSignagure>
        for AuthorityId
    {
        type RuntimeAppPublic = Public;
        type GenericSignature = sp_core::ecdsa::Signature;
        type GenericPublic = sp_core::ecdsa::Public;
    }
}

//TODO Maybe this should be upstreamed into Frontier (And renamed accordingly) so that it can
// be used in palletEVM as well. It may also need more traits such as AsRef, AsMut, etc like
// AccountId32 has.

/// The account type to be used in Moonbeam. It is a wrapper for 20 fixed bytes. We prefer to use
/// a dedicated type to prevent using arbitrary 20 byte arrays were AccountIds are expected. With
/// the introduction of the `scale-info` crate this benefit extends even to non-Rust tools like
/// Polkadot JS.

#[derive(
    Eq, PartialEq, Copy, Clone, Encode, Decode, TypeInfo, MaxEncodedLen, Default, PartialOrd, Ord,
)]
pub struct AccountId20(pub [u8; 20]);

#[cfg(feature = "std")]
impl_serde::impl_fixed_hash_serde!(AccountId20, 20);

#[cfg(feature = "std")]
impl std::fmt::Display for AccountId20 {
    //TODO This is a pretty quck-n-dirty implementation. Perhaps we should add
    // checksum casing here? I bet there is a crate for that.
    // Maybe this one https://github.com/miguelmota/rust-eth-checksum
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl core::fmt::Debug for AccountId20 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", H160(self.0))
    }
}

impl From<[u8; 20]> for AccountId20 {
    fn from(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }
}

impl Into<[u8; 20]> for AccountId20 {
    fn into(self) -> [u8; 20] {
        self.0
    }
}

impl From<H160> for AccountId20 {
    fn from(h160: H160) -> Self {
        Self(h160.0)
    }
}

impl Into<H160> for AccountId20 {
    fn into(self) -> H160 {
        H160(self.0)
    }
}

#[cfg(feature = "std")]
impl std::str::FromStr for AccountId20 {
    type Err = &'static str;
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        H160::from_str(input)
            .map(Into::into)
            .map_err(|_| "invalid hex address.")
    }
}

#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
#[derive(Eq, PartialEq, Clone, Encode, Decode, sp_core::RuntimeDebug, TypeInfo)]
pub struct EthereumSignature(ecdsa::Signature);

impl From<ecdsa::Signature> for EthereumSignature {
    fn from(x: ecdsa::Signature) -> Self {
        EthereumSignature(x)
    }
}

impl sp_runtime::traits::Verify for EthereumSignature {
    type Signer = EthereumSigner;
    fn verify<L: sp_runtime::traits::Lazy<[u8]>>(&self, mut msg: L, signer: &AccountId20) -> bool {
        let mut m = [0u8; 32];
        m.copy_from_slice(Keccak256::digest(msg.get()).as_slice());
        match sp_io::crypto::secp256k1_ecdsa_recover(self.0.as_ref(), &m) {
            Ok(pubkey) => {
                // TODO This conversion could use a comment. Why H256 first, then H160?
                // TODO actually, there is probably just a better way to go from Keccak digest.
                AccountId20(H160::from(H256::from_slice(Keccak256::digest(&pubkey).as_slice())).0)
                    == *signer
            }
            Err(sp_io::EcdsaVerifyError::BadRS) => {
                log::error!(target: "evm", "Error recovering: Incorrect value of R or S");
                false
            }
            Err(sp_io::EcdsaVerifyError::BadV) => {
                log::error!(target: "evm", "Error recovering: Incorrect value of V");
                false
            }
            Err(sp_io::EcdsaVerifyError::BadSignature) => {
                log::error!(target: "evm", "Error recovering: Invalid signature");
                false
            }
        }
    }
}

/// Public key for an Ethereum / Moonbeam compatible account
#[derive(
    Eq, PartialEq, Ord, PartialOrd, Clone, Encode, Decode, sp_core::RuntimeDebug, TypeInfo,
)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
pub struct EthereumSigner([u8; 20]);

impl sp_runtime::traits::IdentifyAccount for EthereumSigner {
    type AccountId = AccountId20;
    fn into_account(self) -> AccountId20 {
        AccountId20(self.0)
    }
}

impl From<[u8; 20]> for EthereumSigner {
    fn from(x: [u8; 20]) -> Self {
        EthereumSigner(x)
    }
}

impl From<ecdsa::Public> for EthereumSigner {
    fn from(x: ecdsa::Public) -> Self {
        let decompressed = libsecp256k1::PublicKey::parse_slice(
            &x.0,
            Some(libsecp256k1::PublicKeyFormat::Compressed),
        )
        .expect("Wrong compressed public key provided")
        .serialize();
        let mut m = [0u8; 64];
        m.copy_from_slice(&decompressed[1..65]);
        let account = H160::from(H256::from_slice(Keccak256::digest(&m).as_slice()));
        EthereumSigner(account.into())
    }
}

impl From<libsecp256k1::PublicKey> for EthereumSigner {
    fn from(x: libsecp256k1::PublicKey) -> Self {
        let mut m = [0u8; 64];
        m.copy_from_slice(&x.serialize()[1..65]);
        let account = H160::from(H256::from_slice(Keccak256::digest(&m).as_slice()));
        EthereumSigner(account.into())
    }
}

#[cfg(feature = "std")]
impl std::fmt::Display for EthereumSigner {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(fmt, "ethereum signature: {:?}", H160::from_slice(&self.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sp_core::{ecdsa, Pair};
    use sp_runtime::traits::IdentifyAccount;

    #[test]
    fn test_account_derivation_1() {
        // Test from https://asecuritysite.com/encryption/ethadd
        let secret_key =
            hex::decode("cb6df9de1efca7a3998a8ead4e02159d5fa99c3e0d4fd6432667390bb4726854")
                .unwrap();
        let mut expected_hex_account = [0u8; 20];
        hex::decode_to_slice(
            "976f8456e4e2034179b284a23c0e0c8f6d3da50c",
            &mut expected_hex_account,
        )
        .expect("example data is 20 bytes of valid hex");

        let public_key = ecdsa::Pair::from_seed_slice(&secret_key).unwrap().public();
        let account: EthereumSigner = public_key.into();
        let expected_account = AccountId20::from(expected_hex_account);
        assert_eq!(account.into_account(), expected_account);
    }
    #[test]
    fn test_account_derivation_2() {
        // Test from https://asecuritysite.com/encryption/ethadd
        let secret_key =
            hex::decode("0f02ba4d7f83e59eaa32eae9c3c4d99b68ce76decade21cdab7ecce8f4aef81a")
                .unwrap();
        let mut expected_hex_account = [0u8; 20];
        hex::decode_to_slice(
            "420e9f260b40af7e49440cead3069f8e82a5230f",
            &mut expected_hex_account,
        )
        .expect("example data is 20 bytes of valid hex");

        let public_key = ecdsa::Pair::from_seed_slice(&secret_key).unwrap().public();
        let account: EthereumSigner = public_key.into();
        let expected_account = AccountId20::from(expected_hex_account);
        assert_eq!(account.into_account(), expected_account);
    }
}
