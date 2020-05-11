use super::super::hash::Hashable;
use super::super::hash::Hasher;
use super::super::hash::H256;
use crate::HASH_TYPE;

// The debug version
#[cfg(debug_assertions)]
macro_rules! debug_println {
    ($( $args:expr ),*) => { println!( $( $args ),* ); }
}

// Non-debug version
#[cfg(not(debug_assertions))]
macro_rules! debug_println {
    ($( $args:expr ),*) => {};
}

#[derive(Default, Debug)]
pub struct MMR<T> {
    // height of each node in MMR
    heights: Vec<usize>,

    // for convenient, let's keep a record of what's the maximum height
    // of the forest at the moment
    max_height: usize,

    // again, for convenient, we keep a current length of MMR array
    // without having to call nodes.len() each time
    current_len: usize,

    // each node in the MMR
    // just a H256, but we can change it to something else later,
    // e.g. H384
    nodes: Vec<H256>,

    // we are not intended to save real data
    // but rust need us to use this generic type T
    _real_data: std::marker::PhantomData<T>,
}

#[derive(Debug)]
pub struct MMRProof {
    target_node: H256,
    target_idx: usize,
    proofs: Vec<H256>,
    mmr_size: usize,
    mmr_root: H256,
}

impl<T> MMR<T> {
    pub fn new(data: &[T]) -> Self
    where
        T: Hashable,
    {
        let mut mmr = MMR {
            heights: Vec::new(),
            max_height: 0,
            current_len: 0,
            nodes: Vec::new(),
            // no one should use this
            _real_data: std::marker::PhantomData::<T>,
        };
        // init an empty MMR
        if data.len() == 0 {
            return mmr;
        }
        // else we need to construct the MMR now

        // set up hasher context
        let mut ctx = Hasher::new(&HASH_TYPE);

        for (_idx, d) in data.iter().enumerate() {
            // check number of additional hashes needed to form the forest
            let hashes_needed = mmr.hashes_needed(mmr.current_len);
            debug_println!("hashes needed for idx={:?}: {:?}", _idx, hashes_needed);

            // insert the current node first
            let current_data_hash: H256 = d.hash(&HASH_TYPE);
            mmr.nodes.push(current_data_hash);
            mmr.heights.push(0);
            mmr.current_len += 1;

            // then do the parent nodes if needed
            for h in 0..hashes_needed {
                // let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
                ctx.reset();
                // left node, basically we remove small tree at a time,
                // the order we remove is from small tree to big tree
                // and the tree size is 2^(h+1) - 1
                // where h is the height
                debug_println!(
                    "Left node is: {:?} with idx {:?}",
                    mmr.nodes[mmr.current_len - ((2 << (h)) - 1)],
                    mmr.current_len - ((2 << (h)) - 1)
                );
                ctx.update(mmr.nodes[(mmr.current_len - 1) - ((2 << (h)) - 1)].as_ref());
                // right node, should always be the tail node
                debug_println!(
                    "Right node is: {:?} with idx {:?}",
                    mmr.nodes[mmr.current_len - 1],
                    mmr.current_len - 1
                );
                ctx.update(mmr.nodes[(mmr.current_len - 1)].as_ref());

                // push the hash of two node in
                mmr.nodes.push(ctx.finish().into());
                // push the new height in
                let new_height = mmr.heights.last().unwrap() + 1;
                // check if new height is a new max
                mmr.heights.push(new_height);
                if new_height > mmr.max_height {
                    mmr.max_height = new_height;
                }
                // update the len of mmr
                mmr.current_len += 1;
            }
        }

        return mmr;
    }

    pub fn insert(&mut self, data: &[T])
    where
        T: Hashable,
    {
        // basicially the same as new

        // set up hasher context
        let mut ctx = Hasher::new(&HASH_TYPE);

        for (_idx, d) in data.iter().enumerate() {
            // check number of additional hashes needed to form the forest
            let hashes_needed = self.hashes_needed(self.current_len);
            debug_println!("hashes needed for idx={:?}: {:?}", _idx, hashes_needed);

            // insert the current node first
            let current_data_hash: H256 = d.hash(&HASH_TYPE);
            self.nodes.push(current_data_hash);
            self.heights.push(0);
            self.current_len += 1;

            // then do the parent nodes if needed
            for h in 0..hashes_needed {
                // let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
                ctx.reset();
                // left node, basically we remove small tree at a time,
                // the order we remove is from small tree to big tree
                // and the tree size is 2^(h+1) - 1
                // where h is the height
                debug_println!(
                    "Left node is: {:?} with idx {:?}",
                    self.nodes[self.current_len - ((2 << (h)) - 1)],
                    self.current_len - ((2 << (h)) - 1)
                );
                ctx.update(self.nodes[(self.current_len - 1) - ((2 << (h)) - 1)].as_ref());
                // right node, should always be the tail node
                debug_println!(
                    "Right node is: {:?} with idx {:?}",
                    self.nodes[self.current_len - 1],
                    self.current_len - 1
                );
                ctx.update(self.nodes[(self.current_len - 1)].as_ref());

                // push the hash of two node in
                self.nodes.push(ctx.finish().into());
                // push the new height in
                let new_height = self.heights.last().unwrap() + 1;
                // check if new height is a new max
                self.heights.push(new_height);
                if new_height > self.max_height {
                    self.max_height = new_height;
                }
                // update the len of mmr
                self.current_len += 1;
            }
        }
    }

    /// ``` notrust
    /// now we need to bag the forest!
    ///
    /// Imagine we have a forest like this
    /// Then we start calculatingg final root from right to left
    ///
    ///  So root = hash(p1, hash(p2, p3))    
    ///
    ///     p1
    ///     /\     
    ///    /  \   p2
    ///   /\  /\  /\ p3
    ///  /\/\/\/\/\/\/\
    ///
    ///        /\
    ///       /  \
    ///      /    \
    ///     /\     \
    ///    /  \    /\
    ///   /\  /\  /\ \
    ///  /\/\/\/\/\/\/\
    /// ```
    pub fn get_root(&self) -> H256 {
        // some small edges
        if self.current_len == 0 {
            return [0u8; 32].into();
        }
        if self.current_len == 1 {
            return self.nodes[self.current_len - 1];
        }
        // start with the hight of right most tree
        let mut current_height = self.heights[self.current_len - 1];
        // right tree is out
        let mut nodes_processed = (2 << self.heights[current_height]) - 1;
        // at the beginning, right node should just be the last node in the list
        let mut right_hash = self.nodes[self.current_len - 1];
        // calculate the initial left node index, by removing the right tree
        let right_tree_size = (2 << current_height) - 1;
        // if the right tree is already the whole tree
        if right_tree_size >= self.current_len {
            return right_hash;
        }
        let mut left_idx = (self.current_len - 1) - right_tree_size;
        debug_println!(
            "left_idx={:?}, nodes_processed={:?}, current_height={:?}",
            left_idx,
            nodes_processed,
            current_height
        );

        // set up hasher context
        let mut ctx = Hasher::new(&HASH_TYPE);

        // loop through all possible trees with different heights
        // but also takes care of condition where some trees doesn't exist
        // e.g. at node 15, only tree is height 3 and height 0
        while current_height < self.max_height && nodes_processed < self.current_len {
            // let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
            ctx.reset();
            // left node
            ctx.update(self.nodes[left_idx].as_ref());

            // right node
            ctx.update(right_hash.as_ref());

            right_hash = ctx.finish().into();
            current_height = self.heights[left_idx];
            // processed left tree
            nodes_processed += (2 << self.heights[left_idx]) - 1;
            // update the new left tree index
            // new right tree is old left tree
            let right_tree_size = (2 << current_height) - 1;
            // if the new right tree is already the whole tree
            if right_tree_size >= left_idx {
                return right_hash;
            }
            left_idx -= (2 << current_height) - 1;
            debug_println!(
                "left_idx={:?}, nodes_processed={:?}, current_height={:?}",
                left_idx,
                nodes_processed,
                current_height
            );
        }
        return right_hash;
    }

    /// ```notrust
    /// this function, similar to the function above, bags the mmr forest, and pro
    /// pub fn bag(&self) -> Vec<H256> {}

    /// given incoming index, how many hashes do we need to perform
    /// after insert this node?
    /// example:
    ///  
    /// /  <- needs 0
    /// /\  <- needs 1
    ///
    /// /\ /  <- needs 0
    /// /\ /\  <- needs 2
    ///
    /// NOTE idx is 0 indexed
    /// ```
    fn hashes_needed(&self, idx: usize) -> i32 {
        let mut hashes = 0;
        if idx == 0 {
            return hashes;
        }
        // left nodes always need 0 hashes
        // left node can be seen as:
        // a node inserted right after a small tree is built
        let h = self.heights[idx - 1];
        if h > 0 {
            return hashes;
        }
        let mut idx_local = idx;
        let mut height = 0;

        while height <= self.max_height {
            let offset = (2 << height) - 1;
            if offset > idx_local {
                break;
            }
            // if there exist a same height left node
            // then we need a hash
            if self.heights[idx_local - offset] == height {
                hashes += 1;
                idx_local += 1;
                height += 1;
            } else {
                break;
            }
        }

        // while max_height_seen >= 0 {
        //     // dirty, but basic idea is we gradually take big complete trees
        //     // off the picture, then see how many lonely branches left
        //     // basically equals to idx -= (2^(h+1)-1)
        //     let tree_size = (2 << max_height_seen) - 1;
        //     debug_println!("tree size={:?}", tree_size);
        //     // takes care the edge case where we don't have trees with certain height
        //     // e.g. if we have a complete tree of 15 nodes on left (height=3)
        //     // now we have a small tree of 3 nodes on the right (height=1)
        //     // then we need to skip the height 2, since we don't have it :(
        //     if tree_size > idx_local {
        //         max_height_seen -= 1;
        //         continue;
        //     }
        //     idx_local -= tree_size;
        //     hashes += 1;
        //     max_height_seen -= 1;
        // }
        // if idx_local < 0 {
        //     hashes -= 1;
        // }
        debug_println!("{:?} hashes needed for index {:?}", hashes, idx);
        return hashes;
    }

    /// provide a merkle proof for the node at index idx
    /// idx is 0 indexed
    pub fn proof(&self, idx: usize) -> MMRProof {
        debug_println!(
            "proofing idx {:?}, current mmr len is {:?}",
            idx,
            self.current_len
        );
        if self.current_len == 0 || idx > (self.current_len - 1) {
            return MMRProof {
                target_node: [0u8; 32].into(),
                target_idx: idx,
                proofs: Vec::new(),
                mmr_size: self.current_len,
                mmr_root: [0u8; 32].into(),
            };
        }
        let mut current_idx = idx;
        let mut current_height = self.heights[current_idx];
        let mut proof_array: Vec<H256> = Vec::new();

        // find the peak of current tree
        while current_height <= self.max_height && current_idx < self.current_len - 1 {
            // calculate the potential positions of left or right index
            let offset = (2 << current_height) - 1;
            let right_neigh_idx = current_idx + offset;
            let left_neigh_idx = if offset > current_idx {
                0
            } else {
                current_idx - offset
            };
            // we are at peak, if left is neighbor is higher than us
            // and right neighbor is lower than us
            if (right_neigh_idx >= self.current_len - 1
                || self.heights[right_neigh_idx] < current_height)
                && (left_neigh_idx == 0 || self.heights[left_neigh_idx] > current_height)
            {
                // we are reaching at current tree peak
                break;
            }

            // check if current node is left or right
            // it's a left node if its height is the same as its right neighour
            // or if the current node covers the left most of the tree
            // and right neighbor is inbound
            debug_println!(
                "current_idx={:?}, right_nei_idx={:?}, current_height={:?}",
                current_idx,
                right_neigh_idx,
                current_height
            );
            if right_neigh_idx < self.current_len && current_height == self.heights[right_neigh_idx]
            {
                // let's push its right neighbour then
                proof_array.push(self.nodes[right_neigh_idx]);

                debug_println!(
                    "idx={:?}, height={:?} it's a left node, pushing right neighour at {:?}, jump to {:?} at height {:?}",
                    current_idx,
                    current_height,
                    right_neigh_idx,
                    right_neigh_idx + 1,
                    current_height + 1
                );

                // now move on the to the next level
                current_idx = right_neigh_idx + 1;
                current_height += 1;
            } else {
                // else it's a right node, with no guarantee what the left height could be
                let left_neigh_idx = current_idx - ((2 << current_height) - 1);
                let left_neigh_height = self.heights[left_neigh_idx];

                proof_array.push(self.nodes[left_neigh_idx]);
                // current_idx = left_neigh_idx;
                debug_println!(
                    "idx={:?}, height={:?} it's a right node, pushing left neighour at {:?}, jumping to {:?} at height {:?}",
                    current_idx,
                    current_height,
                    left_neigh_idx,
                    current_idx + 1,
                    left_neigh_height + 1
                );
                // jump to the parent, which is right next to the right node
                current_idx += 1;
                current_height = left_neigh_height + 1;
            }
            debug_println!(
                "next iter: current_idx={:?}, current_height={:?}",
                current_idx,
                current_height
            );
        } // done hiking to current peak

        // now it's time to bag the sub trees on our right
        debug_println!(
            "Done looping: current_idx={:?}, current_height={:?}, current_path={:?}",
            current_idx,
            current_height,
            proof_array
        );

        // set up hasher context
        let mut ctx = Hasher::new(&HASH_TYPE);

        let mut bagging_idx = self.current_len - 1;
        let mut right_hash = self.nodes[bagging_idx];
        let mut bagging_height = self.heights[bagging_idx];
        let mut bagged = false;
        while bagging_idx > current_idx {
            // prepare for hash context
            // let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
            ctx.reset();
            // get left hash
            let offset = (2 << bagging_height) - 1;
            // if the left node is already out of bound,
            // or left node is the current node's tree peak,
            // we don't want a hash with current node's tree peak,
            // since this would be the parent in the proof path, which should be
            //      calculated during verify, and not in the proof itself.
            if offset > bagging_idx || (bagging_idx - offset) <= current_idx {
                break;
            }
            ctx.update(self.nodes[bagging_idx - offset].as_ref());
            // put right hash in
            ctx.update(right_hash.as_ref());

            // get the new root of two trees and move the the left tree
            right_hash = ctx.finish().into();
            bagging_height = self.heights[bagging_idx - offset];
            // update the index to be the left tree's root idx
            bagging_idx -= offset;
            debug_println!(
                "bagging: bagging_idx={:?}, bagging_height={:?}",
                bagging_idx,
                bagging_height
            );
            bagged = true;
        }
        // the proof should include the bagged right trees' root
        // however, we only push if there is 'really' a right tree,
        // not just our own peak
        // or if there is only one tree on our left, we just push that peak
        if bagged || bagging_idx > current_idx {
            proof_array.push(right_hash);
        }

        // after bagging the right, push current node's tree's left peaks from right to left
        while current_idx > 0 {
            let offset = (2 << current_height) - 1;
            // if the left peak's index is out of range already
            if offset > current_idx {
                break;
            }
            // update index to the left peak
            current_idx -= offset;
            debug_println!(
                "pushing left peak: current_idx={:?}, current_height={:?}",
                current_idx,
                current_height
            );
            // push the left hash
            proof_array.push(self.nodes[current_idx]);
            // update to the height of left peak
            current_height = self.heights[current_idx];
        }

        // return proof_array;
        return MMRProof {
            target_node: self.nodes[idx],
            target_idx: idx,
            proofs: proof_array,
            mmr_size: self.current_len,
            mmr_root: self.get_root(),
        };
    }

    /// get the proof of a node with certain hash, useful when we don't know the index
    /// of the node, and we only know the hash of the node
    pub fn proof_with_hash(&self, target_hash: &H256) -> MMRProof {
        for (idx, node) in self.nodes.iter().enumerate() {
            if *node == *target_hash {
                return self.proof(idx);
            }
        }
        // if the we can't find this hash in MMR
        return MMRProof {
            target_node: target_hash.clone(),
            target_idx: self.current_len,
            proofs: Vec::new(),
            mmr_size: self.current_len,
            mmr_root: [0u8; 32].into(),
        };
    }

    /// verify the proof now
    pub fn verify(&self, mmr_proof: &MMRProof) -> bool {
        debug_println!("MMR::verify the proof: {:?}", mmr_proof);
        // small boundary checks
        if mmr_proof.target_idx >= mmr_proof.mmr_size {
            return false;
        }
        // the hash value passed in is diff than our record :(
        if mmr_proof.target_node != self.nodes[mmr_proof.target_idx] {
            return false;
        }
        let heights = Self::_get_heights(mmr_proof.mmr_size);
        let mut current_idx = mmr_proof.target_idx;
        let mut current_height = heights[current_idx];
        let mut current_lvl_hash = mmr_proof.target_node.clone();
        // we keep track if and when we reach the peak at the first time
        // because, for the first time, we hash with the bag root of the right hash(current, right)
        // afterwards we just keep hashing with the left hash(left, current)
        let mut first_time_at_peak = true;

        // set up hasher context
        let mut ctx = Hasher::new(&HASH_TYPE);

        // start from the bottom, move to the top
        for proof_node in mmr_proof.proofs.iter() {
            // prepare a context for this round
            // let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
            ctx.reset();
            let offset = (2 << current_height) - 1;
            let right_neigh_idx = current_idx + offset;
            let left_neigh_idx = if offset > current_idx {
                0
            } else {
                current_idx - offset
            };

            // check if we are already at current peak
            // we are at peak if: we are on the side already (cross the boundaries)
            //                    or the heights are different than our current height
            if (right_neigh_idx >= mmr_proof.mmr_size || heights[right_neigh_idx] < current_height)
                && (left_neigh_idx == 0 || heights[left_neigh_idx] > current_height)
            {
                debug_println!(
                    "Reached peak at idx={:?}, height={:?}, right_nei={:?}, left_nei={:?}",
                    current_idx,
                    current_height,
                    right_neigh_idx,
                    left_neigh_idx
                );
                // we know we are at peak by checking same-height left nodes and right nodes
                // and we know there is none

                // first time get on to the peak, we hash with the bag of right root
                // hash(current, right)
                // even though this is our first time, still need to check
                // if we are already the right-most tree
                // if we are right-most, then just hash with left...
                if first_time_at_peak && current_idx < mmr_proof.mmr_size - 1 {
                    debug_println!("first time reaching peak");
                    first_time_at_peak = false;

                    ctx.update(current_lvl_hash.as_ref());
                    ctx.update(proof_node.as_ref());
                } else {
                    // we also fall in here when we are the right-most node
                    // we need to change the flag as well
                    if first_time_at_peak {
                        first_time_at_peak = false;
                    }
                    debug_println!("hashing with left peak");
                    // future times we just keep hashing with the left peaks
                    // hash(left, current)
                    ctx.update(proof_node.as_ref());
                    ctx.update(current_lvl_hash.as_ref());
                }
                current_lvl_hash = ctx.finish().into();
                // go left
                current_idx = left_neigh_idx;
                current_height = heights[left_neigh_idx];
            } else {
                // if we are not at the current peak yet
                // check if the proof is left proof or right proof
                // it's a left node if its height is the same as its right neighour
                // and right neighbor is inbound
                if right_neigh_idx < mmr_proof.mmr_size
                    && current_height == self.heights[right_neigh_idx]
                {
                    // left node first
                    ctx.update(current_lvl_hash.as_ref());
                    // then right node
                    ctx.update(proof_node.as_ref());

                    current_lvl_hash = ctx.finish().into();
                    // now move on the to the next level
                    current_idx = right_neigh_idx + 1;
                    current_height += 1;

                    debug_println!(
                        "it's a left node, hashing with right neighour at {:?}, jump to {:?}",
                        right_neigh_idx,
                        current_idx
                    );
                } else {
                    // else it's a right node, with no guarantee what the left height could be
                    let left_neigh_height = self.heights[left_neigh_idx];

                    // left node fist
                    ctx.update(proof_node.as_ref());
                    // then right node
                    ctx.update(current_lvl_hash.as_ref());

                    current_lvl_hash = ctx.finish().into();
                    // current_idx = left_neigh_idx;
                    // jump to the parent, which is right next to ourself (right node)
                    current_idx += 1;
                    current_height = left_neigh_height + 1;

                    debug_println!(
                        "it's a right node, hashing with left neighour at {:?}, jumping to {:?}",
                        left_neigh_idx,
                        current_idx
                    );
                }
            }
        }

        // return current_lvl_hash == self.get_root();
        return current_lvl_hash == mmr_proof.mmr_root;
    }

    /// for an array, calculate the heights for each element
    fn _get_heights(mmr_size: usize) -> Vec<usize> {
        let mut mmr_local = mmr_size;
        let mut max_height = 0;
        while mmr_local > 0 {
            mmr_local >>= 1;
            max_height += 1;
        }

        // arr[14] = 3
        // arr[17] = 1
        // [0, 0, 1, 0, 0, 1, 2, 0, 0, 1, 0, 0, 1, 2, 3, 0, 0, 1]
        // dirty: we keep an array of length max_height
        // in this case we count the number of occurences at each node,
        // if the occurence is power of 2, then we know now is the time to insert a higher level node
        let mut node_height_counter: Vec<usize> = vec![0; max_height];
        // the final array we are returning
        let mut heights = vec![0; mmr_size];
        let mut current_lvl: usize = 0;
        // iterate through all the elements, basically do a binary addition with carrys
        for (_idx, node) in heights.iter_mut().enumerate() {
            // if we already seen the node with current height twice
            // means we need to move one level up (carry up)
            // and clear the old level's count
            // e.g. 1 0 -> 2 0 -> 0 1
            if node_height_counter[current_lvl] == 2 {
                current_lvl += 1;
                // reset the counter of previous level
                node_height_counter[current_lvl - 1] = 0;
            }
            // assign current level (after check-and-moving) to current node
            *node = current_lvl;
            // update the count of occurences of current level node
            node_height_counter[current_lvl] += 1;

            // if not enough of current level node seen, re-aggregate from base level
            // since current (upper) level is aggregated from bottom
            // e.g. 0, 0, 1 (drop to bottom), 0, 0, 1 (not drop since we have 2x level-1 nodes)
            if node_height_counter[current_lvl] < 2 {
                current_lvl = 0;
            }
        }
        return heights;
    }

    /// convert an input array index into index in MMR
    /// e.g. we have MMR [0, 0, 1, 0, 0, 1, 2, 0, 0, 1]
    /// we can convert index 3 to 4, index 5 to 8
    pub fn convert_to_mmr_idx(input_idx: usize) -> usize {
        // gradually remove the possible trees from input array
        let mut mmr_idx = input_idx;
        let mut nodes_processed = 0;
        while nodes_processed < input_idx {
            let mut idx_local = input_idx - nodes_processed;
            let mut tree_height = 0;
            // pre take 1 for correctness
            idx_local >>= 1;
            while idx_local > 0 {
                idx_local >>= 1;
                tree_height += 1;
            }
            debug_println!("Conversion: tree height is {:?}", tree_height);
            nodes_processed += 1 << tree_height;
            mmr_idx += (1 << tree_height) - 1;
        }
        return mmr_idx;
    }

    /// given the size of the mmr
    /// return the peaks' locations and their height
    /// return valuse are all 0 indexed
    pub fn get_peaks(mmr_size: usize) -> Vec<(usize, usize)> {
        let mut peaks: Vec<(usize, usize)> = Vec::new();
        if mmr_size == 0 {
            return peaks;
        }
        if mmr_size == 1 {
            peaks.push((0, 0));
            return peaks;
        }
        // this marks the location of peaks and its corresponding heights
        let mut processed_size = 0;
        // record the max height so later use
        let mut max_height = 0;
        // method is keep finding the largest power of two's in the size of the tree
        // since each tree size = 2^(height) - 1
        while processed_size < mmr_size {
            let mmr_local = mmr_size - processed_size;
            // notice that the height we get here is different
            // it's 1 higher than the normal height we use,
            // since in normal height, it starts at level 0
            let mut height = 0;
            // basically keep removing the largets possible trees
            loop {
                if (1 << height + 1) - 1 > mmr_local {
                    break;
                }
                height += 1;
            }

            // debug_println!("height {:?}", height);

            // height here is 1 indexed, so we -1 before putting into the peak array
            // -1 for 0 indexing, -1 for size(tree) = (2^(height)) - 1
            peaks.push((processed_size + (1 << height) - 1 - 1, height - 1));
            // new start point, beside the leftmost tree
            processed_size += (1 << height) - 1;
            if max_height == 0 {
                max_height = height;
            }
            // debug_println!("processed_size {:?}", processed_size);
        }
        return peaks;
    }

    pub fn get_hash_at(&self, idx: usize) -> H256 {
        if idx > self.current_len - 1 {
            return [0u8; 32].into();
        }
        return self.nodes[idx];
    }

    pub fn get_size(&self) -> usize {
        return self.current_len;
    }

    pub fn print_dbg(&self) {
        debug_println!(
            "MMR: Nodes are {:?}, \
             Heights are {:?}, \
             Current len is {:?}, \
             Max height is {:?}",
            self.nodes,
            self.heights,
            self.current_len,
            self.max_height
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::H256;
    // use bincode;

    #[test]
    fn construct_empty_node() {
        let empty: Vec<H256> = Vec::new();
        let mut mmr = MMR::new(&empty);
        for node in empty.into_iter() {
            mmr.insert(&vec![node]);
        }
        println!("{:?}", mmr.get_root());

        assert_eq!(
            mmr.get_root(),
            hex!("0000000000000000000000000000000000000000000000000000000000000000").into()
        );
    }

    #[test]
    fn construct_single_node() {
        let input: Vec<H256> =
            vec![hex!("0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d").into()];
        let mmr = MMR::new(&input);
        mmr.print_dbg();
        // print!("{:?}", mmr.);

        assert_eq!(
            mmr.get_root(),
            (hex!("b69566be6e1720872f73651d1851a0eae0060a132cf0f64a0ffaea248de6cba0")).into()
        );

        let empty: Vec<H256> = Vec::new();
        let mut mmr = MMR::new(&empty);
        for node in input.into_iter() {
            mmr.insert(&vec![node]);
        }

        assert_eq!(
            mmr.get_root(),
            hex!("b69566be6e1720872f73651d1851a0eae0060a132cf0f64a0ffaea248de6cba0").into()
        );
    }

    #[test]
    fn construct_double_node() {
        let input: Vec<H256> = vec![
            hex!("0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d").into(),
            (hex!("0101010101010101010101010101010101010101010101010101010101010202")).into(),
        ];
        let mmr = MMR::new(&input);
        mmr.print_dbg();
        println!("root hash is {:?}", mmr.get_root());
        assert_eq!(
            mmr.get_root(),
            (hex!("6b787718210e0b3b608814e04e61fde06d0df794319a12162f287412df3ec920")).into()
        );
        println!("Proofs for 0 is: {:?}", mmr.proof(0));
        println!("Proofs for 1 is: {:?}", mmr.proof(1));

        let empty: Vec<H256> = Vec::new();
        let mut mmr = MMR::new(&empty);
        for node in input.into_iter() {
            mmr.insert(&vec![node]);
        }

        assert_eq!(
            mmr.get_root(),
            hex!("6b787718210e0b3b608814e04e61fde06d0df794319a12162f287412df3ec920").into()
        );
    }

    #[test]
    fn construct_tripple_node() {
        let input: Vec<H256> = vec![
            hex!("0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d").into(),
            (hex!("0101010101010101010101010101010101010101010101010101010101010202")).into(),
            (hex!("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f")).into(),
        ];
        let mmr = MMR::new(&input);
        mmr.print_dbg();
        println!("root hash is {:?}", mmr.get_root());
        assert_eq!(
            mmr.get_root(),
            (hex!("803132c20187edf39bf8bda091f5a18b7636a561e7baea8a44b66abbb5233459")).into()
        );

        let empty: Vec<H256> = Vec::new();
        let mut mmr = MMR::new(&empty);
        for node in input.into_iter() {
            mmr.insert(&vec![node]);
        }

        assert_eq!(
            mmr.get_root(),
            hex!("803132c20187edf39bf8bda091f5a18b7636a561e7baea8a44b66abbb5233459").into()
        );
    }

    #[test]
    fn construct_four_node() {
        let input: Vec<H256> = vec![
            hex!("0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d").into(),
            (hex!("0101010101010101010101010101010101010101010101010101010101010202")).into(),
            (hex!("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f")).into(),
            (hex!("0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a")).into(),
        ];
        let mmr = MMR::new(&input);
        mmr.print_dbg();
        println!("root hash is {:?}", mmr.get_root());
        assert_eq!(
            mmr.get_root(),
            (hex!("9fa2c4790f864188b21964c64ed2b819093a0f8355ef26bb0e21272fa138568f")).into()
        );
        // println!("Proofs for 0 is: {:?}", mmr.proof(0));
        println!("Proofs for 4 is: {:?}", mmr.proof(4));

        let empty: Vec<H256> = Vec::new();
        let mut mmr = MMR::new(&empty);
        for node in input.into_iter() {
            mmr.insert(&vec![node]);
        }

        assert_eq!(
            mmr.get_root(),
            hex!("9fa2c4790f864188b21964c64ed2b819093a0f8355ef26bb0e21272fa138568f").into()
        );
    }

    #[test]
    fn construct_five_node() {
        time_test!();
        let input: Vec<H256> = vec![
            hex!("0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d").into(),
            (hex!("0101010101010101010101010101010101010101010101010101010101010202")).into(),
            (hex!("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f")).into(),
            (hex!("0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a")).into(),
            (hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")).into(),
        ];
        let mmr = MMR::new(&input);
        mmr.print_dbg();
        println!("root hash is {:?}", mmr.get_root());
        assert_eq!(
            mmr.get_root(),
            (hex!("027c60a23121a81d3462b38dffdce03e824c22374f2a5b91e52a0c8dbe4d27cd")).into()
        );

        let empty: Vec<H256> = Vec::new();
        let mut mmr = MMR::new(&empty);
        for node in input.into_iter() {
            mmr.insert(&vec![node]);
        }

        assert_eq!(
            mmr.get_root(),
            hex!("027c60a23121a81d3462b38dffdce03e824c22374f2a5b91e52a0c8dbe4d27cd").into()
        );
    }

    /// tests
    ///
    ///    top
    ///    / \    top
    ///   /\ /\   / \  
    #[test]
    fn construct_six_node() {
        time_test!();
        let input: Vec<H256> = vec![
            hex!("0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d").into(),
            (hex!("0101010101010101010101010101010101010101010101010101010101010202")).into(),
            (hex!("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f")).into(),
            (hex!("0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a")).into(),
            (hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")).into(),
            (hex!("0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a")).into(),
        ];
        let mmr = MMR::new(&input);
        mmr.print_dbg();
        println!("root hash is {:?}", mmr.get_root());
        assert_eq!(
            mmr.get_root(),
            (hex!("a692508f99fdb399c150548429c82bebc1449272d0332f87a9f75d5236bb2b8f")).into()
        );

        let empty: Vec<H256> = Vec::new();
        let mut mmr = MMR::new(&empty);
        for node in input.into_iter() {
            mmr.insert(&vec![node]);
        }

        assert_eq!(
            mmr.get_root(),
            hex!("a692508f99fdb399c150548429c82bebc1449272d0332f87a9f75d5236bb2b8f").into()
        );
    }

    /// tests
    ///
    ///    top
    ///    / \    top
    ///   /\ /\   / \  /
    #[test]
    fn construct_seven_node() {
        time_test!();
        let input: Vec<H256> = vec![
            hex!("0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d").into(),
            (hex!("0101010101010101010101010101010101010101010101010101010101010202")).into(),
            (hex!("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f")).into(),
            (hex!("0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a")).into(),
            (hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")).into(),
            (hex!("0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a")).into(),
            (hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")).into(),
        ];

        let mmr = MMR::new(&input);

        assert_eq!(
            mmr.get_root(),
            hex!("a6234d1190212b5cf597809a1dc8921315ba598dbb3ac173b360b57b57a89290").into()
        );

        let empty: Vec<H256> = Vec::new();
        let mut mmr = MMR::new(&empty);
        for node in input.into_iter() {
            mmr.insert(&vec![node]);
        }

        assert_eq!(
            mmr.get_root(),
            hex!("a6234d1190212b5cf597809a1dc8921315ba598dbb3ac173b360b57b57a89290").into()
        );
    }

    /// tests
    ///       top
    ///     /     \
    ///    / \   / \
    ///   /\ /\ /\ /\
    #[test]
    fn construct_eight_node() {
        time_test!();
        let input: Vec<H256> = vec![
            hex!("0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d").into(),
            (hex!("0101010101010101010101010101010101010101010101010101010101010202")).into(),
            (hex!("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f")).into(),
            (hex!("0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a")).into(),
            (hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")).into(),
            (hex!("0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a")).into(),
            (hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")).into(),
            (hex!("0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a")).into(),
        ];

        let mmr = MMR::new(&input);

        assert_eq!(
            mmr.get_root(),
            hex!("9c3bc81f464a27fdb12619fcd6113aea2dae2b9bdb438d03630ad32f6a1b4a65").into()
        );

        let empty: Vec<H256> = Vec::new();
        let mut mmr = MMR::new(&empty);
        for node in input.into_iter() {
            mmr.insert(&vec![node]);
        }

        assert_eq!(
            mmr.get_root(),
            hex!("9c3bc81f464a27fdb12619fcd6113aea2dae2b9bdb438d03630ad32f6a1b4a65").into()
        );
    }

    /// tests
    ///       top
    ///     /     \
    ///    / \   / \   
    ///   /\ /\ /\ /\ /
    #[test]
    fn construct_nine_node() {
        time_test!();
        let input: Vec<H256> = vec![
            hex!("0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d").into(),
            (hex!("0101010101010101010101010101010101010101010101010101010101010202")).into(),
            (hex!("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f")).into(),
            (hex!("0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a")).into(),
            (hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")).into(),
            (hex!("0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a")).into(),
            (hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")).into(),
            (hex!("0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a")).into(),
            hex!("0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d").into(),
        ];

        let mmr = MMR::new(&input);

        assert_eq!(
            mmr.get_root(),
            hex!("64431e691d526bb429e74c08392725c30bdd4267e26a40fa67aef4e23a3e1d22").into()
        );

        let empty: Vec<H256> = Vec::new();
        let mut mmr = MMR::new(&empty);
        for node in input.into_iter() {
            mmr.insert(&vec![node]);
        }

        assert_eq!(
            mmr.get_root(),
            hex!("64431e691d526bb429e74c08392725c30bdd4267e26a40fa67aef4e23a3e1d22").into()
        );
    }

    /// tests
    ///       top
    ///     /     \
    ///    / \   / \   top
    ///   /\ /\ /\ /\  / \
    #[test]
    fn construct_ten_node() {
        time_test!();
        let input: Vec<H256> = vec![
            hex!("0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d").into(),
            (hex!("0101010101010101010101010101010101010101010101010101010101010202")).into(),
            (hex!("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f")).into(),
            (hex!("0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a")).into(),
            (hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")).into(),
            (hex!("0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a")).into(),
            (hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")).into(),
            (hex!("0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a")).into(),
            hex!("0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d").into(),
            (hex!("0101010101010101010101010101010101010101010101010101010101010202")).into(),
        ];

        let mmr = MMR::new(&input);

        assert_eq!(
            mmr.get_root(),
            hex!("aded7e7dea5572260a5855163e8fff2665305020d93bbf43215128441f2ac6f8").into()
        );

        let empty: Vec<H256> = Vec::new();
        let mut mmr = MMR::new(&empty);
        for node in input.into_iter() {
            mmr.insert(&vec![node]);
        }

        assert_eq!(
            mmr.get_root(),
            hex!("aded7e7dea5572260a5855163e8fff2665305020d93bbf43215128441f2ac6f8").into()
        );
    }

    #[test]
    fn proof_empty_node() {
        let empty: Vec<H256> = Vec::new();
        let mut mmr = MMR::new(&empty);
        for node in empty.into_iter() {
            mmr.insert(&vec![node]);
        }

        let mmr_size = mmr.get_size();
        // test both in bound and out of bound
        for i in 0..(mmr_size + 10) {
            if i < mmr_size {
                assert_eq!(mmr.verify(&mmr.proof(i)), true);
            } else {
                assert_eq!(mmr.verify(&mmr.proof(i)), false);
            }
        }
    }

    #[test]
    fn proof_one_node() {
        time_test!();
        let input: Vec<H256> =
            vec![hex!("0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d").into()];
        let mmr: MMR<H256> = MMR::new(&input);
        mmr.print_dbg();
        let mmr_size = mmr.get_size();
        // test both in bound and out of bound
        for i in 0..(mmr_size + 10) {
            if i < mmr_size {
                assert_eq!(mmr.verify(&mmr.proof(i)), true);
            } else {
                assert_eq!(mmr.verify(&mmr.proof(i)), false);
            }
        }
    }

    #[test]
    fn proof_three_node() {
        time_test!();
        let input: Vec<H256> = vec![
            hex!("0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d").into(),
            (hex!("0101010101010101010101010101010101010101010101010101010101010202")).into(),
            (hex!("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f")).into(),
        ];
        let mmr: MMR<H256> = MMR::new(&input);
        // mmr.print_dbg();
        let mmr_size = mmr.get_size();
        // test both in bound and out of bound
        for i in 0..(mmr_size + 10) {
            if i < mmr_size {
                assert_eq!(mmr.verify(&mmr.proof(i)), true);
            } else {
                assert_eq!(mmr.verify(&mmr.proof(i)), false);
            }
        }
    }

    #[test]
    fn proof_four_node() {
        time_test!();
        let input: Vec<H256> = vec![
            hex!("0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d").into(),
            (hex!("0101010101010101010101010101010101010101010101010101010101010202")).into(),
            (hex!("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f")).into(),
            (hex!("0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a")).into(),
        ];
        let mmr: MMR<H256> = MMR::new(&input);
        // mmr.print_dbg();
        let mmr_size = mmr.get_size();
        // test both in bound and out of bound
        for i in 0..(mmr_size + 10) {
            if i < mmr_size {
                assert_eq!(mmr.verify(&mmr.proof(i)), true);
            } else {
                assert_eq!(mmr.verify(&mmr.proof(i)), false);
            }
        }
    }

    #[test]
    fn proof_six_node() {
        time_test!();
        let input: Vec<H256> = vec![
            hex!("0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d").into(),
            (hex!("0101010101010101010101010101010101010101010101010101010101010202")).into(),
            (hex!("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f")).into(),
            (hex!("0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a")).into(),
            (hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")).into(),
            (hex!("0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a")).into(),
        ];
        let mmr = MMR::new(&input);
        mmr.print_dbg();
        let mmr_size = mmr.get_size();
        // test both in bound and out of bound
        for i in 0..(mmr_size + 10) {
            if i < mmr_size {
                assert_eq!(mmr.verify(&mmr.proof(i)), true);
            } else {
                assert_eq!(mmr.verify(&mmr.proof(i)), false);
            }
        }
    }

    #[test]
    fn proof_seven_node() {
        time_test!();
        let input: Vec<H256> = vec![
            hex!("0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d").into(),
            (hex!("0101010101010101010101010101010101010101010101010101010101010202")).into(),
            (hex!("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f")).into(),
            (hex!("0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a")).into(),
            (hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")).into(),
            (hex!("0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a")).into(),
            (hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")).into(),
        ];
        let mmr = MMR::new(&input);
        mmr.print_dbg();
        let mmr_size = mmr.get_size();

        // test both in bound and out of bound
        for i in 0..(mmr_size + 10) {
            if i < mmr_size {
                assert_eq!(mmr.verify(&mmr.proof(i)), true);
            } else {
                assert_eq!(mmr.verify(&mmr.proof(i)), false);
            }
        }
    }

    /// ultimate test
    #[test]
    fn proof_25_node() {
        time_test!();
        let input: Vec<H256> =
            vec![
                hex!("0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d").into();
                25
            ];
        let mmr = MMR::new(&input);
        mmr.print_dbg();
        let mmr_size = mmr.get_size();

        // test both in bound and out of bound
        for i in 0..(mmr_size + 10) {
            if i < mmr_size {
                assert_eq!(mmr.verify(&mmr.proof(i)), true);
            } else {
                assert_eq!(mmr.verify(&mmr.proof(i)), false);
            }
        }
    }

    #[test]
    fn proof_1000_node() {
        time_test!();
        let input: Vec<H256> =
            vec![
                hex!("0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d").into();
                1000
            ];
        let mmr = MMR::new(&input);
        mmr.print_dbg();
        let mmr_size = mmr.get_size();

        // test both in bound and out of bound
        for i in 0..(mmr_size + 10) {
            if i < mmr_size {
                assert_eq!(mmr.verify(&mmr.proof(i)), true);
            } else {
                assert_eq!(mmr.verify(&mmr.proof(i)), false);
            }
        }
    }

    #[test]
    fn test_index_conversion() {
        let mmr_idx = MMR::<H256>::convert_to_mmr_idx(28);
        assert_eq!(mmr_idx, 53);
    }
}

/*
0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a: b9b07dd4e7718454476f04edeb935022ae4f4d90934ab7ce913ff20c8baeb399
0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b: f0e38b830ebd8a506615ecd154330ec07ff6bf5030447b44e297db1d4b7514ac
0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f: 9b68d49bb092f71292ad76ab8fb8750d710aae5af70e43b8ec0a901d048c0030
0101010101010101010101010101010101010101010101010101010101010202: 965b093a75a75895a351786dd7a188515173f6928a8af8c9baa4dcff268a4f0f
0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d0a0b0c0d0e0f0e0d: b69566be6e1720872f73651d1851a0eae0060a132cf0f64a0ffaea248de6cba0


*/
