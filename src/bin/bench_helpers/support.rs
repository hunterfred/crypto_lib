use digest::Digest;
use merklemountainrange::merklenode::ObjectHash;
use tari_utilities::Hashable;

use blake2b_rs::{Blake2b, Blake2bBuilder};
use bytes::Bytes;
use ckb_merkle_mountain_range::Merge;

pub struct TestObject<D: Digest> {
    pub id: String,
    pub hasher: D,
}

impl<D: Digest> TestObject<D> {
    pub fn new(id: String) -> TestObject<D> {
        let hasher = D::new();
        TestObject { id, hasher }
    }
}

impl<D: Digest> Hashable for TestObject<D> {
    fn hash(&self) -> ObjectHash {
        let mut hash = D::new();
        hash.input(self.id.as_bytes());
        hash.result().to_vec()
    }
}

// ======for ckb_merkle_mountain_range======

fn new_blake2b() -> Blake2b {
    Blake2bBuilder::new(32).build()
}

#[derive(Eq, PartialEq, Clone, Debug, Default)]
pub struct NumberHash(pub Bytes);
// impl From<u32> for NumberHash {
//     fn from(num: u32) -> Self {
//         let mut hasher = new_blake2b();
//         let mut hash = [0u8; 32];
//         hasher.update(&num.to_le_bytes());
//         hasher.finalize(&mut hash);
//         NumberHash(hash.to_vec().into())
//     }
// }
impl From<[u8; 32]> for NumberHash {
    fn from(input: [u8; 32]) -> Self {
        let mut hasher = new_blake2b();
        let mut hash = [0u8; 32];
        hasher.update(&input);
        hasher.finalize(&mut hash);
        NumberHash(hash.to_vec().into())
    }
}

pub struct MergeNumberHash;

impl Merge for MergeNumberHash {
    type Item = NumberHash;
    fn merge(lhs: &Self::Item, rhs: &Self::Item) -> Self::Item {
        let mut hasher = new_blake2b();
        let mut hash = [0u8; 32];
        hasher.update(&lhs.0);
        hasher.update(&rhs.0);
        hasher.finalize(&mut hash);
        NumberHash(hash.to_vec().into())
    }
}
