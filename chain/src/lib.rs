extern crate rustc_hex as hex;
extern crate primitives;
extern crate bitcrypto as crypto;
extern crate serialization as ser;
#[macro_use]
extern crate serialization_derive;
#[cfg(test)]
#[macro_use]
extern crate unwrap;

pub mod constants;

mod block;
mod block_header;
mod merkle_root;
mod transaction;

/// `IndexedBlock` extension
mod read_and_hash;
mod indexed_block;
mod indexed_header;
mod indexed_transaction;

pub trait RepresentH256 {
	fn h256(&self) -> hash::H256;
}

pub use primitives::{hash, bytes, bigint, compact};

pub use block::Block;
pub use block_header::{BlockHeader};
pub use merkle_root::{merkle_root, merkle_node_hash};
pub use transaction::{Transaction, TransactionInput, TransactionOutput, TxHashAlgo, OutPoint, JoinSplit, ShieldedSpend, ShieldedOutput};

pub use read_and_hash::{ReadAndHash, HashedData};
pub use indexed_block::IndexedBlock;
pub use indexed_header::IndexedBlockHeader;
pub use indexed_transaction::IndexedTransaction;

pub type ShortTransactionID = hash::H48;
