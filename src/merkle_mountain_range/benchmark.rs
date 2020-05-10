use super::super::hash::H256;
use super::merkle_mountain_range::{MMRProof, MMR};
use time;

fn proof_1000_node() {
    let input: Vec<H256> =
        vec![hex!("0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d").into(); 1000];
    let current_time = std::time::Instant::now();
    let mmr = MMR::new(&input);
    println!(
        "time took to construct the MMR: {:?}",
        current_time.elapsed()
    );
    // mmr.print_dbg();
    // let mmr_size = mmr.get_size();

    // // test both in bound and out of bound
    // for i in 0..(mmr_size + 10) {
    //     if i < mmr_size {
    //         assert_eq!(mmr.verify(&mmr.proof(i)), true);
    //     } else {
    //         assert_eq!(mmr.verify(&mmr.proof(i)), false);
    //     }
    // }
}
