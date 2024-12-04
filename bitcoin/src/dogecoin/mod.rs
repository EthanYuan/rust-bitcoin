use crate::blockdata::block::{Header, Version};
use crate::blockdata::transaction::Transaction;
use crate::consensus::{
    encode::{self, MAX_VEC_SIZE},
    Decodable, Encodable,
};
pub use crate::hash_types::BlockHash;
use crate::hash_types::TxMerkleNode;
use crate::internal_macros::impl_consensus_encoding;
use crate::io::{self, Read, Write};
use crate::pow::CompactTarget;
use crate::prelude::*;

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
    /// N index
    pub n_index: i32,
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
    n_index,
    blockchain_branch,
    chain_index,
    parent_block_header
);

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

impl DogecoinHeader {
    /// Returns the block hash of the header.
    pub fn block_hash(&self) -> BlockHash {
        let pure_header: Header = self.clone().into();
        pure_header.block_hash()
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
            len += self.auxpow.as_ref().unwrap().consensus_encode(s)?;
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
