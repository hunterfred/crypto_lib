use serde::{Deserialize, Serialize};
use std::hash::Hash;

#[derive(Debug, Default, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct BitVec {
    // Just the bits, nothing but the bits...
    bits: Vec<u8>,
    // Size of the bit array for bounds checking
    pub size: usize,
}

impl BitVec {
    /// Create a new `bitvec` with `size` bits
    pub fn new(size: usize) -> BitVec {
        BitVec {
            bits: vec![0u8; size],
            size: size,
        }
    }

    pub fn is_set(&self, pos: usize) -> bool {
        if pos > self.size {
            panic!("Attempted to index beyond bounds of bit vector.");
        }
        (self.bits[pos / 8] & 1 << (pos % 8)) != 0u8
    }

    /// Set the bit at `pos` to 1
    pub fn set(&mut self, pos: usize) {
        if pos > self.size {
            panic!("Attempted to index beyond bounds of bit vector.");
        }
        // for example if pos = 10 -> pos/8 = 1, pos%8 = 2
        self.bits[pos / 8] |= 1 << (pos % 8);
    }
}

#[test]
fn bit_vec_create_test() {
    let tester: BitVec = BitVec::new(8);
    assert!(tester.bits[0] == 0);
}

#[test]
fn bit_vec_set_test() {
    let mut tester: BitVec = BitVec::new(8);
    tester.set(5);
    assert!(tester.bits[0] == 32);
    let res = tester.is_set(5);
    assert!(res == true);
}

#[test]
fn bit_vec_is_set_test() {
    let mut tester: BitVec = BitVec::new(8);
    tester.set(5);
    assert!(tester.is_set(5) == true);
    assert!(tester.is_set(6) == false);
}

#[test]
#[should_panic]
fn bit_vec_out_of_bounds_test() {
    let mut tester: BitVec = BitVec::new(8);
    tester.set(15);
}
