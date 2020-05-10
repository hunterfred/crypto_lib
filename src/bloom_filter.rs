use crate::bit_vec::BitVec;
use fasthash::murmur3::hash32_with_seed;
use serde::{Deserialize, Serialize};
use std::hash::Hash;

#[derive(Debug, Default, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct BloomFilter {
    pub bits: BitVec,
    num_hashes: usize,
}

impl BloomFilter {
    pub fn new(expected_inserts: usize, fpr: f64) -> Self {
        if fpr <= 0.0 {
            panic!("False positive rate must be larger than 0.0");
        }
        // bit_vec size = -n * ln(fpr) / ((ln2)^2)
        let m =
            ((-1.0 * (expected_inserts as f64) * fpr.ln()) / 2.0f64.ln().powf(2.0)).ceil() as usize;
        // num_hashes = k = (bit_vec_size / expected_inserts) * ln(2)
        let k: usize = (((m as f64) / (expected_inserts as f64)) * 2.0f64.ln()).ceil() as usize;
        BloomFilter {
            bits: BitVec::new(m),
            num_hashes: k,
        }
    }
    pub fn insert(&mut self, value: &[u8]) {
        for i in 0..self.num_hashes {
            let bit_idx = hash32_with_seed(value, i as u32) % (self.bits.size as u32);
            self.bits.set(bit_idx as usize);
        }
    }

    pub fn maybe_present(&self, value: &[u8]) -> bool {
        for i in 0..self.num_hashes {
            let bit_idx = hash32_with_seed(value, i as u32) % (self.bits.size as u32);
            if !self.bits.is_set(bit_idx as usize) {
                return false;
            }
        }
        return true;
    }
}

#[test]
fn test_insert_and_check() {
    let mut bf = BloomFilter::new(2, 0.01);
    bf.insert("test".as_ref());
    assert!(bf.maybe_present("test".as_ref()));
}

#[test]
fn test_multiple_insert_and_check() {
    let mut bf = BloomFilter::new(10, 0.001);
    let animals = [
        "cat", "dog", "ant", "bear", "bird", "cow", "horse", "kitten", "lion", "puppy",
    ];
    for animal in animals.iter() {
        assert!(!bf.maybe_present(animal.as_ref()));
    }
    for animal in animals.iter() {
        bf.insert(animal.as_ref());
        assert!(bf.maybe_present(animal.as_ref()));
    }
}
