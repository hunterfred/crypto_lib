#[macro_use]
extern crate hex_literal;

pub mod bench_helpers;

use blake2;
use ckb_merkle_mountain_range;
use crypto_lib;
use merklemountainrange;

pub fn test_mmr(mmr_size: usize) {
    let input: Vec<crypto_lib::hash::H256> =
        vec![
            hex!("0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d").into();
            mmr_size
        ];
    let mut current_time = std::time::Instant::now();
    let mmr = crypto_lib::merkle_mountain_range::merkle_mountain_range::MMR::new(&input);
    println!(
        "time took to construct the MMR of size {:?}: {:?}",
        input.len(),
        current_time.elapsed()
    );
    current_time = std::time::Instant::now();
    let proof = mmr.proof(0);
    println!(
        "time took to get proof from the MMR of size {:?}: {:?}",
        input.len(),
        current_time.elapsed()
    );
    current_time = std::time::Instant::now();
    let _res = mmr.verify(&proof);
    assert_eq!(_res, true);
    println!(
        "time took to verify proof the MMR of size {:?}: {:?}",
        input.len(),
        current_time.elapsed()
    );
    // test merklemountainrange crate in crates.io

    // ======construct======
    current_time = std::time::Instant::now();
    let mut other_mmr_1 = merklemountainrange::merklemountainrange::MerkleMountainRange::<
        bench_helpers::support::TestObject<blake2::Blake2b>,
        blake2::Blake2b,
    >::new();
    for i in input.iter() {
        let object: bench_helpers::support::TestObject<blake2::Blake2b> =
            bench_helpers::support::TestObject::new(i.to_string());
        other_mmr_1.add_single(object);
    }
    println!(
        "time took for merklemountainrange to construct the MMR of size {:?}: {:?}",
        input.len(),
        current_time.elapsed()
    );

    // ======proof======
    current_time = std::time::Instant::now();
    let _proof = other_mmr_1.get_hash_proof(&other_mmr_1.get_hash(0).unwrap());
    println!(
        "time took for merklemountainrange to get proof from the MMR of size {:?}: {:?}",
        input.len(),
        current_time.elapsed()
    );

    // ======verify======
    current_time = std::time::Instant::now();
    let _res = other_mmr_1.verify_proof(&_proof);
    println!(
        "time took for merklemountainrange to verify proof the MMR of size {:?}: {:?}",
        input.len(),
        current_time.elapsed()
    );
    // test ckb_merkle_mountain_range crate in crates.io

    // ======construct======
    current_time = std::time::Instant::now();
    let store = ckb_merkle_mountain_range::util::MemStore::default();
    let mut ckb_mmr =
        ckb_merkle_mountain_range::MMR::<_, bench_helpers::support::MergeNumberHash, _>::new(
            0, &store,
        );
    for i in input.iter() {
        let obj = bench_helpers::support::NumberHash::from(Into::<[u8; 32]>::into(i));
        ckb_mmr.push(obj).expect("push");
    }
    // ckb_mmr.commit().expect("commit changes");
    println!(
        "time took for ckb_merkle_mountain_range to construct the MMR of size {:?}: {:?}",
        input.len(),
        current_time.elapsed()
    );

    // ======proof======
    current_time = std::time::Instant::now();
    let _proof = ckb_mmr.gen_proof(vec![0]).expect("gen proof");
    println!(
        "time took for ckb_merkle_mountain_range to get proof from the MMR of size {:?}: {:?}",
        input.len(),
        current_time.elapsed()
    );
    // ckb_mmr.commit().expect("commit changes");

    // ======verify======
    current_time = std::time::Instant::now();
    let _res = _proof.verify(
        ckb_mmr.get_root().expect("get root"),
        vec![(
            0,
            bench_helpers::support::NumberHash::from(Into::<[u8; 32]>::into(input[0])),
        )],
    );
    println!(
        "time took for ckb_merkle_mountain_range to verify proof the MMR of size {:?}: {:?}",
        input.len(),
        current_time.elapsed()
    );
}

pub fn main() {
    test_mmr(630000);
}
