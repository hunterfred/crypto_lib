#[macro_use]
extern crate hex_literal;

use crypto_lib;

pub fn test_mmr(mmr_size: usize) {
    let input: Vec<crypto_lib::hash::H256> =
        vec![
            hex!("0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d").into();
            mmr_size
        ];
    let mut current_time = std::time::Instant::now();
    let mmr = crypto_lib::merkle_mountain_range::merkle_mountain_range::MMR::new(&input);
    println!(
        "time took to construct the MMR: {:?}",
        current_time.elapsed()
    );
    current_time = std::time::Instant::now();
    let proof = mmr.proof(0);
    println!(
        "time took to get from the MMR: {:?}",
        current_time.elapsed()
    );
    current_time = std::time::Instant::now();
    let _res = mmr.verify(&proof);
    assert_eq!(_res, true);
    println!(
        "time took to verify proof the MMR: {:?}",
        current_time.elapsed()
    );
}

pub fn main() {
    test_mmr(630000);
}
