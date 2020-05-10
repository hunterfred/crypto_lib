use super::super::hash::{Hashable, H256};
use log::debug;
use ring;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct MerkleProof {
    pub tx_hash: H256,
    pub tx_index: usize,
    pub block_merkle_root: H256,
    pub proof: Vec<H256>,
}

/// A Merkle tree.
#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct MerkleTree<T> {
    root_node: Option<Box<Node<T>>>,
    height: i64,
    num_leaf: i64,
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
struct Node<T> {
    // data is only here when leaf node
    data: Option<T>,
    // but hash resides in every level
    hash: Vec<u8>,
    left: Option<Box<Node<T>>>,
    right: Option<Box<Node<T>>>,
    is_leaf: bool,
}

impl<T> MerkleTree<T> {
    pub fn new(data: &[T]) -> Self
    where
        T: Hashable,
    {
        // unimplemented!()
        let mut construct_queue: VecDeque<Node<T>> = VecDeque::new();
        // iterate through the slice of data, put them in leaf node of merkle tree
        for leaf in data.into_iter() {
            let leaf_tree_node: Node<T> = Node {
                data: None, // can't copy the data... can't store it in tree then...
                hash: (*leaf).hash().as_ref().to_vec(),
                left: None,
                right: None,
                is_leaf: true,
            };
            construct_queue.push_back(leaf_tree_node);
        }
        // loop until we have only 1 node left: the root
        // some book keeping info
        let mut height: i64 = 1;
        let num_leaf = construct_queue.len();
        while construct_queue.len() > 1 {
            // next level
            let mut next_lvl: VecDeque<Node<T>> = VecDeque::new();
            // let's start the current level construction
            height += 1;
            while !construct_queue.is_empty() {
                if let Some(left) = construct_queue.pop_front() {
                    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
                    ctx.update(&left.hash);
                    let right_ptr: Option<Box<Node<T>>>;
                    // when we have even number of nodes, good
                    if let Some(right_test) = construct_queue.pop_front() {
                        ctx.update(&right_test.hash);
                        right_ptr = Some(Box::new(right_test));
                    }
                    // else if right node is missing, when data is in odd number, we need to copy the left node to right
                    else {
                        ctx.update(&left.hash);
                        right_ptr = None;
                    }
                    let middle_node: Node<T> = Node {
                        data: None,
                        hash: ctx.finish().as_ref().to_vec(),
                        left: Some(Box::new(left)),
                        right: right_ptr,
                        is_leaf: false,
                    };
                    next_lvl.push_back(middle_node);
                }
            }
            // current level construction done, let's move one level up
            construct_queue = next_lvl;
        }
        // now we only have one node (root) left in queue
        if let Some(root) = construct_queue.pop_front() {
            let the_merkle_tree: MerkleTree<T> = MerkleTree {
                root_node: Some(Box::new(root)),
                height: height,
                num_leaf: num_leaf as i64,
            };
            return the_merkle_tree;
        } else {
            panic!(
                "Merkle Tree PANIC: There is no root left during construction. \
                 Data has length of: {:?} \
                 height of current construction is {:?} \
                 num_leaf={:?} \
                 construct_queue has length is {:?}",
                data.len(),
                height,
                num_leaf,
                construct_queue.len()
            )
        }
    }

    // helper function to convert Vec<u8> to H256 hash
    pub fn convert_to_h256(hash_vec: &Vec<u8>) -> H256 {
        let mut hash_val: [u8; 32] = [0; 32];
        hash_val.copy_from_slice(&hash_vec[0..32]);
        return H256::from(hash_val);
    }

    pub fn root(&self) -> H256 {
        if let Some(root) = &self.root_node {
            Self::convert_to_h256(&root.hash)
        } else {
            panic!("There is no root in the tree.");
        }
    }

    /// Returns the Merkle Proof of data at index i
    pub fn proof(&self, index: usize) -> Vec<H256> {
        // unimplemented!()
        let mut hash_seq: Vec<H256> = Vec::new();
        if index > (self.num_leaf as usize - 1) {
            panic!("you are questing a non-existing leaf");
        }
        let mut current_node: Option<&Box<Node<T>>> = self.root_node.as_ref();
        let mut left_bound = 0;
        let mut right_bound = 2i64.pow(self.height as u32 - 1) - 1;
        // print!("height is {}, right bound is {}", self.height, right_bound);
        while (hash_seq.len() as i64) < (self.height - 1) {
            // if current node is not None
            if let Some(cur) = current_node {
                let split = (left_bound + right_bound + 1) / 2;
                // if we need to go left, we put the right hash in
                if (index as i64) < split {
                    if let Some(right) = cur.right.as_ref() {
                        hash_seq.push(Self::convert_to_h256(&right.hash));
                    }
                    // but if the node is in odd number, we push left hash in, which is the right since right = dup(left)
                    else if let Some(left) = cur.left.as_ref() {
                        hash_seq.push(Self::convert_to_h256(&left.hash));
                    }
                    current_node = cur.left.as_ref();
                    right_bound = split;
                }
                // else we need to go right, we put the left hash in
                else {
                    if let Some(left) = cur.left.as_ref() {
                        hash_seq.push(Self::convert_to_h256(&left.hash));
                    }
                    current_node = cur.right.as_ref();
                    left_bound = split;
                }
            }
        }
        return hash_seq;
    }
}

/// Verify that the datum hash with a vector of proofs will produce the Merkle root. Also need the
/// index of datum and `leaf_size`, the total number of leaves.
pub fn verify(root: &H256, datum: &H256, proof: &[H256], index: usize, _leaf_size: usize) -> bool {
    // unimplemented!()
    let mut path_len = proof.len();
    let mut hash_val: H256 = datum.clone();
    // let mut current_hash_ref: &[u8] = hash_val.as_ref();
    let mut cur_idx = index as i64;
    while path_len > 0 {
        path_len -= 1;
        // prepare a context for this round
        let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
        // check if this datum is in left branch or right branch
        // if datum is left
        if cur_idx % 2 == 0 {
            ctx.update(hash_val.as_ref());
            ctx.update(proof[path_len].as_ref());
        }
        // else if datum is right
        else {
            ctx.update(proof[path_len].as_ref());
            ctx.update(hash_val.as_ref());
        }
        cur_idx /= 2;
        hash_val = H256::from(ctx.finish());
        // debug!("merkel: hash_val {:?}", hash_val);
    }
    return hash_val == *root;
}
/*
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hash::H256;

    macro_rules! gen_merkle_tree_data {
        () => {{
            vec![
                (hex!("0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d")).into(),
                (hex!("0101010101010101010101010101010101010101010101010101010101010202")).into(),
            ]
        }};
    }

    #[test]
    fn root() {
        let input_data: Vec<H256> = gen_merkle_tree_data!();
        let merkle_tree = MerkleTree::new(&input_data);
        let root = merkle_tree.root();
        assert_eq!(
            root,
            (hex!("6b787718210e0b3b608814e04e61fde06d0df794319a12162f287412df3ec920")).into()
        );
        // "b69566be6e1720872f73651d1851a0eae0060a132cf0f64a0ffaea248de6cba0" is the hash of
        // "0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d"
        // "965b093a75a75895a351786dd7a188515173f6928a8af8c9baa4dcff268a4f0f" is the hash of
        // "0101010101010101010101010101010101010101010101010101010101010202"
        // "6b787718210e0b3b608814e04e61fde06d0df794319a12162f287412df3ec920" is the hash of
        // the concatenation of these two hashes "b69..." and "965..."
        // notice that the order of these two matters
    }

    #[test]
    fn proof() {
        let input_data: Vec<H256> = gen_merkle_tree_data!();
        let merkle_tree = MerkleTree::new(&input_data);
        let proof = merkle_tree.proof(0);
        assert_eq!(
            proof,
            vec![hex!("965b093a75a75895a351786dd7a188515173f6928a8af8c9baa4dcff268a4f0f").into()]
        );
        // "965b093a75a75895a351786dd7a188515173f6928a8af8c9baa4dcff268a4f0f" is the hash of
        // "0101010101010101010101010101010101010101010101010101010101010202"
    }

    #[test]
    fn verifying() {
        let input_data: Vec<H256> = gen_merkle_tree_data!();
        let merkle_tree = MerkleTree::new(&input_data);
        let proof = merkle_tree.proof(0);
        assert!(verify(
            &merkle_tree.root(),
            &input_data[0].hash(),
            &proof,
            0,
            input_data.len()
        ));
    }
}
*/

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::H256;
    use bincode;

    macro_rules! gen_merkle_tree_data {
        () => {{
            vec![
                (hex!("0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d")).into(),
                (hex!("0101010101010101010101010101010101010101010101010101010101010202")).into(),
            ]
        }};
    }

    macro_rules! gen_merkle_tree_single_node {
        () => {{
            vec![(hex!("0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d")).into()]
        }};
    }

    macro_rules! gen_merkle_tree_three_node {
        () => {{
            vec![
                (hex!("0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d")).into(),
                (hex!("0101010101010101010101010101010101010101010101010101010101010202")).into(),
                (hex!("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f")).into(),
            ]
        }};
    }

    macro_rules! gen_merkle_tree_five_node {
        () => {{
            vec![
                (hex!("0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d")).into(),
                (hex!("0101010101010101010101010101010101010101010101010101010101010202")).into(),
                (hex!("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f")).into(),
                (hex!("0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a")).into(),
                (hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")).into(),
            ]
        }};
    }
    #[test]
    fn root() {
        let input_data: Vec<H256> = gen_merkle_tree_data!();
        let merkle_tree = MerkleTree::new(&input_data);
        let root = merkle_tree.root();
        assert_eq!(
            root,
            (hex!("6b787718210e0b3b608814e04e61fde06d0df794319a12162f287412df3ec920")).into()
        );
        // "b69566be6e1720872f73651d1851a0eae0060a132cf0f64a0ffaea248de6cba0" is the hash of
        // "0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d"
        // "965b093a75a75895a351786dd7a188515173f6928a8af8c9baa4dcff268a4f0f" is the hash of
        // "0101010101010101010101010101010101010101010101010101010101010202"
        // "6b787718210e0b3b608814e04e61fde06d0df794319a12162f287412df3ec920" is the hash of
        // the concatenation of these two hashes "b69..." and "965..."
        // notice that the order of these two matters
    }

    #[test]
    fn root_single_node() {
        let input_data: Vec<H256> = gen_merkle_tree_single_node!();
        let merkle_tree = MerkleTree::new(&input_data);
        let root = merkle_tree.root();
        assert_eq!(
            root,
            (hex!("b69566be6e1720872f73651d1851a0eae0060a132cf0f64a0ffaea248de6cba0")).into()
        );
    }

    #[test]
    fn root_three_node() {
        let input_data: Vec<H256> = gen_merkle_tree_three_node!();
        let merkle_tree = MerkleTree::new(&input_data);
        let root = merkle_tree.root();
        assert_eq!(
            root,
            (hex!("b74fc755f6dd1bf3bf56431f046dcf4b789dd8fc26dd4a5b19e2c6cdd971bcf9")).into()
        );
    }
    #[test]
    fn root_five_node() {
        let input_data: Vec<H256> = gen_merkle_tree_five_node!();
        let merkle_tree = MerkleTree::new(&input_data);
        let root = merkle_tree.root();
        assert_eq!(
            root,
            (hex!("7b4ef80e66a4e54ccd1125d4d2c72048186961d93d1c901c3e6a897dc30f67ac")).into()
        );
    }

    #[test]
    fn proof() {
        let input_data: Vec<H256> = gen_merkle_tree_data!();
        let merkle_tree = MerkleTree::new(&input_data);
        let proof = merkle_tree.proof(0);
        assert_eq!(
            proof,
            vec![hex!("965b093a75a75895a351786dd7a188515173f6928a8af8c9baa4dcff268a4f0f").into()]
        );
        // "965b093a75a75895a351786dd7a188515173f6928a8af8c9baa4dcff268a4f0f" is the hash of
        // "0101010101010101010101010101010101010101010101010101010101010202"
    }

    #[test]
    fn proof_three_node() {
        let input_data: Vec<H256> = gen_merkle_tree_three_node!();
        let merkle_tree = MerkleTree::new(&input_data);
        let proof_idx0 = merkle_tree.proof(0);
        assert_eq!(
            proof_idx0,
            vec![
                hex!("8e8a90b58bc4eaa86157687d509ed46018a91f199a16e5f76fe6b6d755d6e71a").into(),
                hex!("965b093a75a75895a351786dd7a188515173f6928a8af8c9baa4dcff268a4f0f").into(),
            ]
        );
        let proof_idx1 = merkle_tree.proof(1);
        assert_eq!(
            proof_idx1,
            vec![
                hex!("8e8a90b58bc4eaa86157687d509ed46018a91f199a16e5f76fe6b6d755d6e71a").into(),
                hex!("b69566be6e1720872f73651d1851a0eae0060a132cf0f64a0ffaea248de6cba0").into(),
            ]
        );
        let proof_idx2 = merkle_tree.proof(2);
        assert_eq!(
            proof_idx2,
            vec![
                hex!("6b787718210e0b3b608814e04e61fde06d0df794319a12162f287412df3ec920").into(),
                hex!("9b68d49bb092f71292ad76ab8fb8750d710aae5af70e43b8ec0a901d048c0030").into(),
            ]
        );
        // let proof_idx3 = merkle_tree.proof(3);
        // assert_eq!(
        //     proof_idx3,
        //     vec![
        //         hex!("6b787718210e0b3b608814e04e61fde06d0df794319a12162f287412df3ec920").into(),
        //         hex!("9b68d49bb092f71292ad76ab8fb8750d710aae5af70e43b8ec0a901d048c0030").into(),
        //     ]
        // );
    }

    #[test]
    fn verifying() {
        let input_data: Vec<H256> = gen_merkle_tree_data!();
        let merkle_tree = MerkleTree::new(&input_data);
        let proof = merkle_tree.proof(0);
        assert!(verify(
            &merkle_tree.root(),
            &input_data[0].hash(),
            &proof,
            0,
            input_data.len()
        ));
    }

    #[test]
    fn verifying_single_node() {
        let input_data: Vec<H256> = gen_merkle_tree_single_node!();
        let merkle_tree = MerkleTree::new(&input_data);
        let proof = merkle_tree.proof(0);
        assert!(verify(
            &merkle_tree.root(),
            &input_data[0].hash(),
            &proof,
            0,
            input_data.len()
        ));
    }

    #[test]
    fn verifying_three_node() {
        let input_data: Vec<H256> = gen_merkle_tree_three_node!();
        let merkle_tree = MerkleTree::new(&input_data);
        let proof = merkle_tree.proof(0);
        // println!("proof trail {:?}", proof);
        assert!(verify(
            &merkle_tree.root(),
            &input_data[0].hash(),
            &proof,
            0,
            input_data.len()
        ));
    }
    #[test]
    fn verifying_five_node() {
        let input_data: Vec<H256> = gen_merkle_tree_five_node!();
        let merkle_tree = MerkleTree::new(&input_data);
        let proof = merkle_tree.proof(3);
        println!("proof trail {:?}", proof);
        assert!(verify(
            &merkle_tree.root(),
            &input_data[3].hash(),
            &proof,
            3,
            input_data.len()
        ));
    }
}
