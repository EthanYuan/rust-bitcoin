//! Dogecoin-specific data structures and functions.

use core::convert::TryInto;
use core::fmt;
use scrypt::{scrypt, Params};

use crate::blockdata::block::{Header, ValidationError, Version};
use crate::blockdata::transaction::Transaction;
use crate::consensus::{
    encode::{self, MAX_VEC_SIZE},
    Decodable, Encodable,
};
use crate::hash_types::TxMerkleNode;
pub use crate::hash_types::{BlockHash, Txid};
use crate::hashes::{sha256d, Hash, HashEngine};
use crate::internal_macros::impl_consensus_encoding;
use crate::io::{self, Read, Write};
use crate::merkle_tree::PartialMerkleTree;
use crate::pow::{CompactTarget, Target, U256};
use crate::prelude::*;

const MERGED_MINING_HEADER: &[u8] = b"\xfa\xbe\x6d\x6d";

/// Implement traits and methods shared by `Target` and `Work`.
macro_rules! do_impl {
    ($ty:ident) => {
        impl $ty {
            /// Creates `Self` from a big-endian byte array.
            #[inline]
            pub fn from_be_bytes(bytes: [u8; 32]) -> $ty {
                $ty(U256::from_be_bytes(bytes))
            }

            /// Creates `Self` from a little-endian byte array.
            #[inline]
            pub fn from_le_bytes(bytes: [u8; 32]) -> $ty {
                $ty(U256::from_le_bytes(bytes))
            }

            /// Converts `self` to a big-endian byte array.
            #[inline]
            pub fn to_be_bytes(self) -> [u8; 32] {
                self.0.to_be_bytes()
            }

            /// Converts `self` to a little-endian byte array.
            #[inline]
            pub fn to_le_bytes(self) -> [u8; 32] {
                self.0.to_le_bytes()
            }
        }

        impl fmt::Display for $ty {
            #[inline]
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                fmt::Display::fmt(&self.0, f)
            }
        }

        impl fmt::LowerHex for $ty {
            #[inline]
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                fmt::LowerHex::fmt(&self.0, f)
            }
        }

        impl fmt::UpperHex for $ty {
            #[inline]
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                fmt::UpperHex::fmt(&self.0, f)
            }
        }
    };
}

/// The auxpow
#[derive(PartialEq, Eq, Clone, Debug, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct AuxPow {
    /// The parent block's coinbase transaction.
    pub coinbase_tx: Transaction,
    /// Block hash
    pub block_hash: BlockHash,
    /// The Merkle branch of the coinbase tx to the parent block's root.
    pub coinbase_branch: Vec<TxMerkleNode>,
    /// Coinbase index
    pub coinbase_index: i32,
    /// The merkle branch connecting the aux block to our coinbase.
    pub blockchain_branch: Vec<TxMerkleNode>,
    /// Merkle tree index of the aux block header in the coinbase.
    pub chain_index: i32,
    /// Parent block header (on which the real PoW is done).
    pub parent_block_header: Header,
}

impl_consensus_encoding!(
    AuxPow,
    coinbase_tx,
    block_hash,
    coinbase_branch,
    coinbase_index,
    blockchain_branch,
    chain_index,
    parent_block_header
);

impl AuxPow {
    /// Returns the block hash of the header.
    pub fn check(
        &self,
        is_strict_chain_id: bool,
        block_hash: BlockHash,
    ) -> Result<(), ValidationError> {
        if self.coinbase_index != 0 {
            return Err(ValidationError::BadAuxPow);
        }

        // Aux POW parent cannot has our chain ID 0x0062
        if is_strict_chain_id && self.parent_block_header.get_chain_id() == 98 {
            return Err(ValidationError::BadAuxPow);
        }

        // Check that the blockchain branch is valid
        if self.blockchain_branch.len() > 30 {
            return Err(ValidationError::BadAuxPow);
        }

        // Check that the chain merkle root is in the coinbase
        let chain_root_hash = check_merkle_branch(
            block_hash.to_raw_hash(),
            &self.blockchain_branch,
            self.chain_index,
        )?;
        let mut reversed_chain_root_hash = chain_root_hash.to_byte_array();
        reversed_chain_root_hash.reverse();

        // Check that we are in the parent block merkle tree
        if self.parent_block_header.merkle_root
            != check_merkle_branch(
                self.coinbase_tx.txid().into(),
                &self.coinbase_branch,
                self.coinbase_index,
            )?
            .into()
        {
            return Err(ValidationError::BadAuxPow);
        }

        // Extract the coinbase script and ensure it contains the merged mining header and root hash
        let script = self.coinbase_tx.input[0].script_sig.to_bytes();

        // Find merged mining header
        let mm_header_pos = script
            .windows(MERGED_MINING_HEADER.len())
            .position(|window| window == MERGED_MINING_HEADER);

        // Check for chain merkle root in coinbase
        let root_hash_pos = script
            .windows(reversed_chain_root_hash.len())
            .position(|window| window == reversed_chain_root_hash);
        if root_hash_pos.is_none() {
            return Err(ValidationError::BadAuxPow);
        }

        if let Some(header_pos) = mm_header_pos {
            // Enforce only one chain merkle root by checking that a single instance of the merged
            // mining header exists just before.
            let second_mm_header = script
                .iter()
                .skip(header_pos + MERGED_MINING_HEADER.len())
                .position(|&b| b == MERGED_MINING_HEADER[0]);

            if second_mm_header.is_some() {
                return Err(ValidationError::BadAuxPow);
            }
            if header_pos + MERGED_MINING_HEADER.len() != root_hash_pos.unwrap() {
                return Err(ValidationError::BadAuxPow);
            }
        } else {
            // For backward compatibility.
            // Enforce only one chain merkle root by checking that it starts early in the coinbase.
            // 8-12 bytes are enough to encode extraNonce and nBits.
            if root_hash_pos.unwrap() > 20 {
                return Err(ValidationError::BadAuxPow);
            }
        }

        // Ensure we are at a deterministic point in the merkle leaves by hashing
        // a nonce and our chain ID and comparing to the index.
        let remaining = &script[root_hash_pos.unwrap() + reversed_chain_root_hash.len()..];
        if remaining.len() < 8 {
            return Err(ValidationError::BadAuxPow);
        }
        let merkle_size = u32::from_le_bytes(remaining[0..4].try_into().unwrap());
        let nonce = u32::from_le_bytes(remaining[4..8].try_into().unwrap());
        if merkle_size != (1 << self.blockchain_branch.len()) as u32 {
            return Err(ValidationError::BadAuxPow);
        }
        if self.chain_index as u32 != get_expected_index(nonce, 98, self.blockchain_branch.len()) {
            return Err(ValidationError::BadAuxPow);
        }

        Ok(())
    }
}

/// Merkle branch verification based on the provided `TxMerkleNode` and the index
fn check_merkle_branch(
    hash: sha256d::Hash,
    branch: &[TxMerkleNode],
    index: i32,
) -> Result<sha256d::Hash, ValidationError> {
    if index < 0 {
        return Err(ValidationError::BadAuxPow);
    }

    let mut current_hash = hash;
    let mut idx = index as usize;
    for merkle_node in branch {
        if idx & 1 == 1 {
            current_hash = hash_internal(merkle_node.to_raw_hash(), current_hash)?;
        } else {
            current_hash = hash_internal(current_hash, merkle_node.to_raw_hash())?;
        }
        idx >>= 1;
    }

    Ok(current_hash.into())
}

/// Helper function to handle hash operation between two nodes in the Merkle branch
fn hash_internal(
    left: sha256d::Hash,
    right: sha256d::Hash,
) -> Result<sha256d::Hash, ValidationError> {
    // Here you would hash the concatenation of the two hashes
    let mut hasher = sha256d::Hash::engine();
    hasher.input(left.as_ref());
    hasher.input(right.as_ref());
    Ok(sha256d::Hash::from_engine(hasher))
}

/// Chooses a pseudo-random slot in the chain merkle tree,
/// but ensures it is fixed for a given size/nonce/chain combination.
///
/// This prevents the same work from being reused for the same chain
/// and reduces the likelihood of two chains clashing for the same slot.
///
/// Note:
/// - This computation can overflow the `u32` used. However, this is not an issue,
///   since the result is taken modulo a power-of-two, ensuring consistency.
/// - The computation remains consistent even if performed in 64 bits,
///   as it was on some systems in the past.
/// - The `h` parameter is always <= 30, as enforced by the maximum allowed chain
///   merkle branch length, so 32 bits are sufficient for the computation.
fn get_expected_index(n_nonce: u32, n_chain_id: u32, h: usize) -> u32 {
    let mut rand = n_nonce;
    rand = rand.wrapping_mul(1103515245).wrapping_add(12345);
    rand = rand.wrapping_add(n_chain_id);
    rand = rand.wrapping_mul(1103515245).wrapping_add(12345);

    rand % (1 << h)
}

impl Header {
    /// Returns the chain id of the block.
    pub fn get_chain_id(&self) -> i32 {
        self.version.0 >> 16
    }

    /// Returns the block hash.
    pub fn block_pow_hash(&self) -> BlockHash {
        // Serialize Header into a byte vector
        let mut header_data = Vec::new();
        self.consensus_encode(&mut header_data).expect("Failed to serialize Header");

        // Scrypt requires a salt, which is the header data itself
        let salt = &header_data;

        // Set up Scrypt parameters (N=2^10, r=1, p=1, dk_len=32)
        let params = Params::new(10, 1, 1, 32).unwrap(); // dk_len=32, output is a 32-byte hash

        // Calculate hash using scrypt
        let mut result = vec![0u8; 32]; // Allocate a 32-byte Vec to store the result
        scrypt(&header_data, salt, &params, &mut result).expect("Scrypt computation failed");

        BlockHash::from_slice(&result).unwrap()
    }

    /// Checks that the proof-of-work for the block is valid, returning the block hash.
    pub fn validate_doge_pow(&self, required_target: Target) -> Result<BlockHash, ValidationError> {
        let pow_hash = self.block_pow_hash();
        if required_target.is_met_by(pow_hash) {
            Ok(self.block_hash())
        } else {
            Err(ValidationError::BadProofOfWork)
        }
    }
}

/// Dogecoin block header.
#[derive(PartialEq, Eq, Clone, Debug, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct DogecoinHeader {
    /// Block version, now repurposed for soft fork signalling.
    pub version: Version,
    /// Reference to the previous block in the chain.
    pub prev_blockhash: BlockHash,
    /// The root hash of the merkle tree of transactions in the block.
    pub merkle_root: TxMerkleNode,
    /// The timestamp of the block, as claimed by the miner.
    pub time: u32,
    /// The target value below which the blockhash must lie.
    pub bits: CompactTarget,
    /// The nonce, selected to obtain a low enough blockhash.
    pub nonce: u32,
    /// The auxpow info
    pub auxpow: Option<AuxPow>,
}

/// Data structure that represents a block header paired to a partial merkle tree.
///
/// NOTE: This assumes that the given Block has *at least* 1 transaction. If the Block has 0 txs,
/// it will hit an assertion.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct DogeMerkleBlock {
    /// The block header
    pub header: DogecoinHeader,
    /// Transactions making up a partial merkle tree
    pub txn: PartialMerkleTree,
    /// Transactions that matched the filter
    pub matched_txn: Vec<(u32, Txid)>,
}

impl DogecoinHeader {
    /// Returns the block hash of the header.
    pub fn block_hash(&self) -> BlockHash {
        let pure_header: Header = self.clone().into();
        pure_header.block_hash()
    }

    /// Returns whether the block is a legacy block.
    pub fn is_legacy(&self) -> bool {
        self.version.0 == 1
        // Dogecoin: We have a random v2 block with no AuxPoW, treat as legacy
        || (self.version.0 == 2 && self.get_chain_id() == 0)
    }

    /// Returns the chain id of the block.
    pub fn get_chain_id(&self) -> i32 {
        self.version.0 >> 16
    }

    /// Returns whether the block is an auxpow block.
    pub fn is_auxpow(&self) -> bool {
        self.version.0 & (1 << 8) != 0
    }

    /// Checks that the proof-of-work for the block is valid, returning the block hash.
    pub fn validate_doge_pow(
        &self,
        is_strict_chain_id: bool,
    ) -> Result<BlockHash, ValidationError> {
        // Dogecoin main fStrictChainId set true
        // Dogecoin testnet fStrictChainId set false
        // Dogecoin main/testnet nAuxpowChainId set 0x0062
        if !self.is_legacy() && is_strict_chain_id && self.get_chain_id() != 98 {
            return Err(ValidationError::BadVersion);
        }

        let pure_header: Header = self.clone().into();

        // Check that the proof-of-work is correct
        if self.auxpow.is_none() {
            if self.is_auxpow() {
                return Err(ValidationError::BadVersion);
            }
            return pure_header.validate_doge_pow(pure_header.target());
        }

        // Check auxpow
        if !self.is_auxpow() {
            return Err(ValidationError::BadVersion);
        }
        let auxpow = self.auxpow.as_ref().expect("auxpow");
        auxpow.check(is_strict_chain_id, pure_header.block_hash())?;
        // Check that the parent block's proof-of-work is correct
        auxpow.parent_block_header.validate_doge_pow(pure_header.target())?;

        Ok(self.block_hash())
    }
}

impl Decodable for DogecoinHeader {
    #[inline]
    fn consensus_decode_from_finite_reader<R: Read + ?Sized>(
        d: &mut R,
    ) -> Result<Self, encode::Error> {
        let version: Version = Decodable::consensus_decode_from_finite_reader(d)?;
        let prev_blockhash = Decodable::consensus_decode_from_finite_reader(d)?;
        let merkle_root = Decodable::consensus_decode_from_finite_reader(d)?;
        let time = Decodable::consensus_decode_from_finite_reader(d)?;
        let bits = Decodable::consensus_decode_from_finite_reader(d)?;
        let nonce = Decodable::consensus_decode_from_finite_reader(d)?;

        let auxpow = if version.to_consensus() & (1 << 8) != 0 {
            Some(Decodable::consensus_decode_from_finite_reader(d)?)
        } else {
            None
        };

        Ok(Self { bits, merkle_root, nonce, time, prev_blockhash, version, auxpow })
    }

    #[inline]
    fn consensus_decode<R: Read + ?Sized>(d: &mut R) -> Result<Self, encode::Error> {
        let mut d = d.take(MAX_VEC_SIZE as u64);

        let version: Version = Decodable::consensus_decode(d.by_ref())?;
        let prev_blockhash = Decodable::consensus_decode(d.by_ref())?;
        let merkle_root = Decodable::consensus_decode(d.by_ref())?;
        let time = Decodable::consensus_decode(d.by_ref())?;
        let bits = Decodable::consensus_decode(d.by_ref())?;
        let nonce = Decodable::consensus_decode(d.by_ref())?;

        let auxpow = if version.to_consensus() & (1 << 8) != 0 {
            Some(Decodable::consensus_decode(d.by_ref())?)
        } else {
            None
        };

        Ok(Self { bits, merkle_root, nonce, time, prev_blockhash, version, auxpow })
    }
}

impl Encodable for DogecoinHeader {
    #[inline]
    fn consensus_encode<R: Write + ?Sized>(&self, s: &mut R) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.version.consensus_encode(s)?;
        len += self.prev_blockhash.consensus_encode(s)?;
        len += self.merkle_root.consensus_encode(s)?;
        len += self.time.consensus_encode(s)?;
        len += self.bits.consensus_encode(s)?;
        len += self.nonce.consensus_encode(s)?;
        if self.version.to_consensus() & (1 << 8) != 0 {
            len += self.auxpow.as_ref().expect("auxpow").consensus_encode(s)?;
        }

        Ok(len)
    }
}

impl From<DogecoinHeader> for Header {
    fn from(dogecoin_header: DogecoinHeader) -> Self {
        Header {
            version: dogecoin_header.version,
            prev_blockhash: dogecoin_header.prev_blockhash,
            merkle_root: dogecoin_header.merkle_root,
            time: dogecoin_header.time,
            bits: dogecoin_header.bits,
            nonce: dogecoin_header.nonce,
        }
    }
}

impl From<Header> for DogecoinHeader {
    fn from(header: Header) -> Self {
        DogecoinHeader {
            version: header.version,
            prev_blockhash: header.prev_blockhash,
            merkle_root: header.merkle_root,
            time: header.time,
            bits: header.bits,
            nonce: header.nonce,
            auxpow: None,
        }
    }
}

impl Encodable for Vec<(u32, Txid)> {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        for item in self {
            len += item.consensus_encode(w)?;
        }
        Ok(len)
    }
}

impl Decodable for Vec<(u32, Txid)> {
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let mut vec = Vec::new();
        while let Ok(item) = Decodable::consensus_decode(r) {
            vec.push(item);
        }
        Ok(vec)
    }
}

impl Encodable for DogeMerkleBlock {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.header.consensus_encode(w)?;
        len += self.txn.consensus_encode(w)?;
        len += self.matched_txn.consensus_encode(w)?;
        Ok(len)
    }
}

impl Decodable for DogeMerkleBlock {
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Ok(DogeMerkleBlock {
            header: Decodable::consensus_decode(r)?,
            txn: Decodable::consensus_decode(r)?,
            matched_txn: Decodable::consensus_decode(r)?,
        })
    }
}

/// A 256 bit integer representing target.
///
/// The SHA-256 hash of a block's header must be lower than or equal to the current target for the
/// block to be accepted by the network. The lower the target, the more difficult it is to generate
/// a block. (See also [`Work`].)
///
/// ref: <https://en.bitcoin.it/wiki/Target>
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct DogecoinTarget(U256);

impl DogecoinTarget {
    /// The maximum possible target.
    ///
    /// This value is used to calculate difficulty, which is defined as how difficult the current
    /// target makes it to find a block relative to how difficult it would be at the highest
    /// possible target. Remember highest target == lowest difficulty.
    ///
    /// ref: <https://en.bitcoin.it/wiki/Target>
    // In Dogecoind this is ~(u256)0 >> 20 stored as a floating-point type so it gets truncated, hence
    // the low 220 bits are all zero.
    pub const MAX: Self = DogecoinTarget(U256(0xFFFF_u128 << (220 - 128), 0));
}
do_impl!(DogecoinTarget);

impl From<DogecoinTarget> for Target {
    fn from(target: DogecoinTarget) -> Target {
        Target(target.0)
    }
}

#[cfg(test)]
mod tests {
    use hex::test_hex_unwrap as hex;

    use super::*;
    use crate::consensus::encode::deserialize;

    #[test]
    fn test_validate_pow_without_auxpow() {
        // Dogecoin header testnet #6,724,076
        let doge_header = hex!("0400620048d3e10f5ac12fcb86e8606bd51797ee0790d59411cd30479122a25dfaf68975d65a1bf34b83ad7737ebb2ca122c77918768e6bbfecb140aa9551b3ecb267cf1cd854867dafd031e8000869b");
        let doge_header: DogecoinHeader =
            deserialize(&doge_header).expect("Can't deserialize correct block header");
        let pure_header: Header = doge_header.clone().into();
        assert!(!doge_header.is_auxpow());
        assert_eq!(doge_header.validate_doge_pow(false).unwrap(), doge_header.block_hash());

        // test with modified header
        let mut invalid_header: Header = pure_header;
        invalid_header.version.0 += 1;
        match invalid_header.validate_doge_pow(invalid_header.target()) {
            Err(ValidationError::BadProofOfWork) => (),
            _ => panic!("unexpected result from validate_pow"),
        }
    }

    #[test]
    fn test_validate_pow_with_auxpow() {
        // Dogecoin header testnet 6,724,092
        let doge_header = hex!("0401620028e3b7be8dabdaf98b10feeb68cd098a89aec6d1c57779c04839bb0ea64896b8f59bbb6f86e1ed748e5d01eb57876d3f2a0d54126215e6304d63b5618fd5a7feee844867a119011c0000000001000000010000000000000000000000000000000000000000000000000000000000000000ffffffff5b03d7ab3529303043796265724c65617020496e63303000000000ad1b536078daf35f0000000616000000000000002cfabe6d6dc9601974928137bfa1acc393191a81af449b9caf86a8c6f42733ec1470ec1b5f040000007e1224c8ffffffff02205fa012000000001600145755e14e56b05fedd745a51c2de544d3457f18510000000000000000266a24aa21a9ed9b49613bb3f9a020f52637cb365aeb4b6b4bc8aeeed9d14d2417b10fcf17fbb7000000009adaeddcf5b978e0b212384d4ad8013b4c29940b7f8b7ac0250a05092547e34c018fc6e1c2e08c7523e05a989f4777f5b9d1ea3aae63817c2241c2b7ef83f3bbce000000000200000000000000000000000000000000000000000000000000000000000000001b1412dbfd3225fb9a125eaf073c131927edbd8ffd69674b2e865a90954ac78d0200000000000020c8ed13f58fe0872e14663be0c175d3fa76d5ad34965a2d90941939062173fa367f2ae04aae6560d408bb12e9b8a62f9fa4df657a7dd514c9cf3552f07df3bd4fed844867fcff031c074cc901");
        let doge_header: DogecoinHeader =
            deserialize(&doge_header).expect("Can't deserialize correct block header");
        let pure_header: Header = doge_header.clone().into();
        assert!(doge_header.is_auxpow());
        assert_eq!(doge_header.validate_doge_pow(false).unwrap(), doge_header.block_hash());

        // test with modified header
        let mut invalid_header: Header = pure_header;
        invalid_header.version.0 += 1;
        match invalid_header.validate_doge_pow(invalid_header.target()) {
            Err(ValidationError::BadProofOfWork) => (),
            _ => panic!("unexpected result from validate_pow"),
        }
    }

    #[test]
    fn test_validate_pow_2_with_auxpow() {
        // Dogecoin header main 5,501,142
        let doge_header = hex!("04016200412c26f602b70017e8a4b8df573e850143f16fd8e547799101540fedf3474bf68ee4b62c1b2cdd9d650e8be0d04e38f508a30d554aae5fb8607ba3f2302a62eca33e5c67750a011a0000000001000000010000000000000000000000000000000000000000000000000000000000000000ffffffff6403bada2a2cfabe6d6d62fb5d7b198abb6a3ba76e2731c9fc8d39c4c1be723355d4ef38afaf788435ed20000000f09f909f092f4632506f6f6c2f64000000000000000000000000000000000000000000000000000000000000000000000005003a0000003a0000000243f64d25000000001976a914f2910ecaf7bb8d18ed71f0904e0e7456f29ce18288ac0000000000000000266a24aa21a9ededa2001e141501310bd65d715b1e1634836d5cf2dd8b7f4be8e2464b0c708200d9d54c408a7fed50b548c923b718f2c8c0624cd746fb7956ff14ef38d500000000000000072bac15b05f9a59ef4973b6ff8395bc8cbbaaeb5114bf2432ef41a54b381a37f7692723544f01d8318e2181dfc871c28b4aac62df419e425d52d383af8cf34b75df6f43453a9c549d992a57a421bf90d102b02738f6098cd0d2026c1e1650fc89e0a4513869f3b918f90aa6d50b68b8789724f7655aea0c47f82b389018cb20f6cfbe6d9c3fc681ec7630e47adbe74c96f924a9a196ee0ed081f4954ea037f5877160f870ea4ad6253f4e6ecbfe46c000d681a2b08cd3030e9c25b8a7eb6af4574afe2c8629186892dadd158eb5d01d382c77a3728990e4d2dee6aa04ed0ac40300000000050900000000000000000000000000000000000000000000000000000000000000710b1b3f2df407a200dd8321454575d9c8a35228a0cb34775aef1d44a656a7c88ac3fd572bb1c5b2322bcfe0ed1c1c5ac499605a9fe6531669d45366c3e47d92303c2636a3c1b1976e635394782eeace5b2821ed760340d053ba79e49f5e0d883b2e17be83df30a037cd6c6c9d9b93b1a966444089aa4d7e9db6208c0335fb860800000014000020a8f8f697ede59e98f94b1faf74e89d09605cfb4ce305a74ecff428feba6aaae59f2544fc5a6065bfef10bc520fc247f33428287e05f73b0136e943d4535715d7c03e5c6751284e195821988b");
        let doge_header: DogecoinHeader =
            deserialize(&doge_header).expect("Can't deserialize correct block header");
        let pure_header: Header = doge_header.clone().into();
        assert!(doge_header.is_auxpow());
        assert_eq!(doge_header.validate_doge_pow(true).unwrap(), doge_header.block_hash());

        // test with modified header
        let mut invalid_header: Header = pure_header;
        invalid_header.version.0 += 1;
        match invalid_header.validate_doge_pow(invalid_header.target()) {
            Err(ValidationError::BadProofOfWork) => (),
            _ => panic!("unexpected result from validate_pow"),
        }
    }
}
