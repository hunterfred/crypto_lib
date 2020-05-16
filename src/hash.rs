use blake3;
use hex;
use serde::{Deserialize, Serialize};
use std::convert::TryInto;

// sum type: https://tonyarcieri.com/a-quick-tour-of-rusts-type-system-part-1-sum-types-a-k-a-tagged-unions
// https://doc.rust-lang.org/stable/rust-by-example/custom_types/enum.html
// https://www.cs.brandeis.edu/~cs146a/rust/rustbyexample-02-21-2015/enum.html
// https://www.reddit.com/r/rust/comments/ayvdfa/generic_constructor_for_enum/
// https://doc.rust-lang.org/book/ch06-01-defining-an-enum.html
// basically attach an anonymous struct inside, and the struct carries the real hasher
// this way we can merge multiple types of hasher into one union, and use match to determine the hasher type

pub enum Hasher {
    Blake3Hash { hasher: blake3::Hasher },
    RingSHA256 { hasher: ring::digest::Context },
}

pub enum HasherType {
    Blake3Hash,
    RingSHA256,
}

/// An object that can be meaningfully hashed.
pub trait Hashable {
    /// Hash the object using SHA256.
    fn hash(&self, h_type: &HasherType) -> H256;
}

// pub struct Hasher {
//     // internal: blake3::Hasher,
//     internal: HasherType,
// }

impl Hasher {
    pub fn new(h_type: &HasherType) -> Self {
        match *h_type {
            HasherType::Blake3Hash => {
                return Hasher::Blake3Hash {
                    hasher: blake3::Hasher::new(),
                };
            }
            HasherType::RingSHA256 => {
                return Hasher::RingSHA256 {
                    hasher: ring::digest::Context::new(&ring::digest::SHA256),
                };
            }
        }
    }

    pub fn reset(&mut self) {
        match self {
            Hasher::Blake3Hash { hasher } => {
                hasher.reset();
            }
            Hasher::RingSHA256 { hasher } => {
                *hasher = ring::digest::Context::new(&ring::digest::SHA256);
            }
        }
        // self.internal.reset();
    }

    pub fn finish(&self) -> H256 {
        match self {
            Hasher::Blake3Hash { hasher } => {
                return hasher.finalize().into();
            }
            Hasher::RingSHA256 { hasher } => {
                return (*hasher).clone().finish().into();
            }
        }
        // self.internal.finalize().into()
    }

    pub fn update(&mut self, input: &[u8]) {
        match self {
            Hasher::Blake3Hash { hasher } => {
                hasher.update(input);
            }
            Hasher::RingSHA256 { hasher } => {
                hasher.update(input);
            }
        }
        // self.internal.update(input);
    }
}

pub fn get_hasher() -> blake3::Hasher {
    return blake3::Hasher::new();
}

/// A SHA256 hash.
#[derive(Eq, PartialEq, Serialize, Deserialize, Clone, Hash, Default, Copy)]
pub struct H256([u8; 32]); // big endian u256

impl Hashable for H256 {
    fn hash(&self, h_type: &HasherType) -> H256 {
        // ring::digest::digest(&ring::digest::SHA256, &self.0).into()
        // blake3::hash(&self.0).into();
        let mut hasher = Hasher::new(h_type);
        hasher.update(&self.0);
        hasher.finish()
    }
}

impl std::fmt::Display for H256 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let start = if let Some(precision) = f.precision() {
            if precision >= 64 {
                0
            } else {
                32 - precision / 2
            }
        } else {
            0
        };
        for byte_idx in start..32 {
            write!(f, "{:>02x}", &self.0[byte_idx])?;
        }
        Ok(())
    }
}

impl std::fmt::Debug for H256 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        // write!(
        //     f,
        //     "{:>02x}{:>02x}..{:>02x}{:>02x}",
        //     &self.0[0], &self.0[1], &self.0[30], &self.0[31]
        // )
        for byte_idx in 0..32 {
            write!(f, "{:>02x}", &self.0[byte_idx])?;
        }
        Ok(())
    }
}

impl std::convert::AsRef<[u8]> for H256 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::convert::From<&[u8; 32]> for H256 {
    fn from(input: &[u8; 32]) -> H256 {
        let mut buffer: [u8; 32] = [0; 32];
        buffer[..].copy_from_slice(input);
        H256(buffer)
    }
}

impl std::convert::From<&H256> for [u8; 32] {
    fn from(input: &H256) -> [u8; 32] {
        let mut buffer: [u8; 32] = [0; 32];
        buffer[..].copy_from_slice(&input.0);
        buffer
    }
}

impl std::convert::From<[u8; 32]> for H256 {
    fn from(input: [u8; 32]) -> H256 {
        H256(input)
    }
}

impl std::convert::From<H256> for [u8; 32] {
    fn from(input: H256) -> [u8; 32] {
        input.0
    }
}

impl std::convert::From<ring::digest::Digest> for H256 {
    fn from(input: ring::digest::Digest) -> H256 {
        let mut raw_hash: [u8; 32] = [0; 32];
        raw_hash[0..32].copy_from_slice(input.as_ref());
        H256(raw_hash)
    }
}

impl std::convert::From<blake3::Hash> for H256 {
    fn from(input: blake3::Hash) -> H256 {
        let hash_bytes: [u8; 32] = input.into();
        H256(hash_bytes)
    }
}

impl std::convert::From<Vec<u8>> for H256 {
    fn from(hash_vec: Vec<u8>) -> H256 {
        let mut hash_val: [u8; 32] = [0; 32];
        hash_val.copy_from_slice(&hash_vec[0..32]);
        return H256::from(hash_val);
    }
}

impl std::convert::From<String> for H256 {
    fn from(hash_str: String) -> H256 {
        let hash_bytes = hex::decode(hash_str).unwrap();
        let mut hash_val: [u8; 32] = [0; 32];
        hash_val.copy_from_slice(&hash_bytes[0..32]);
        return H256::from(hash_val);
    }
}

impl std::convert::From<H256> for String {
    fn from(hash: H256) -> String {
        let mut hash_str: String = String::new();
        for byte_idx in 0..32 {
            // write!(f, "{:>02x}", &self.0[byte_idx])?;
            hash_str.push_str(format!("{:>02x}", &hash.0[byte_idx]).as_str());
        }
        return hash_str;
    }
}

impl std::convert::From<H256> for H160 {
    fn from(full_hash: H256) -> H160 {
        let mut partial_hash: [u8; 20] = [0; 20];
        partial_hash.copy_from_slice(&full_hash.0[12..]);
        H160(partial_hash)
    }
}

impl Ord for H256 {
    fn cmp(&self, other: &H256) -> std::cmp::Ordering {
        let self_higher = u128::from_be_bytes(self.0[0..16].try_into().unwrap());
        let self_lower = u128::from_be_bytes(self.0[16..32].try_into().unwrap());
        let other_higher = u128::from_be_bytes(other.0[0..16].try_into().unwrap());
        let other_lower = u128::from_be_bytes(other.0[16..32].try_into().unwrap());
        let higher = self_higher.cmp(&other_higher);
        match higher {
            std::cmp::Ordering::Equal => self_lower.cmp(&other_lower),
            _ => higher,
        }
    }
}

impl PartialOrd for H256 {
    fn partial_cmp(&self, other: &H256) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

// for H160
/// A hash with 160 bits, used in btc address .
#[derive(Eq, PartialEq, Serialize, Deserialize, Clone, Hash, Default, Copy)]
pub struct H160([u8; 20]); // big endian u256

// impl Hashable for H160 {
//     fn hash(&self) -> H160 {
//         ring::digest::digest(&ring::digest::SHA256, &self.0).into()
//     }
// }

impl std::fmt::Display for H160 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let start = if let Some(precision) = f.precision() {
            if precision >= 64 {
                0
            } else {
                32 - precision / 2
            }
        } else {
            0
        };
        for byte_idx in start..20 {
            write!(f, "{:>02x}", &self.0[byte_idx])?;
        }
        Ok(())
    }
}

impl std::fmt::Debug for H160 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "{:>02x}{:>02x}..{:>02x}{:>02x}",
            &self.0[0], &self.0[1], &self.0[18], &self.0[19]
        )
    }
}

impl std::convert::AsRef<[u8]> for H160 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::convert::From<&[u8; 20]> for H160 {
    fn from(input: &[u8; 20]) -> H160 {
        let mut buffer: [u8; 20] = [0; 20];
        buffer[..].copy_from_slice(input);
        H160(buffer)
    }
}

impl std::convert::From<&[u8]> for H160 {
    fn from(input: &[u8]) -> H160 {
        let mut buffer: [u8; 20] = [0; 20];
        buffer.copy_from_slice(&input[0..20]);
        H160(buffer)
    }
}

impl std::convert::From<&H160> for [u8; 20] {
    fn from(input: &H160) -> [u8; 20] {
        let mut buffer: [u8; 20] = [0; 20];
        buffer[..].copy_from_slice(&input.0);
        buffer
    }
}

impl std::convert::From<[u8; 20]> for H160 {
    fn from(input: [u8; 20]) -> H160 {
        H160(input)
    }
}

impl std::convert::From<H160> for [u8; 20] {
    fn from(input: H160) -> [u8; 20] {
        input.0
    }
}

impl std::convert::From<ring::digest::Digest> for H160 {
    fn from(input: ring::digest::Digest) -> H160 {
        let mut raw_hash: [u8; 20] = [0; 20];
        raw_hash.copy_from_slice(&input.as_ref()[12..]);
        H160(raw_hash)
    }
}

impl std::convert::From<Vec<u8>> for H160 {
    fn from(hash_vec: Vec<u8>) -> H160 {
        let mut hash_val: [u8; 20] = [0; 20];
        hash_val.copy_from_slice(&hash_vec[0..20]);
        return H160::from(hash_val);
    }
}

impl Ord for H160 {
    fn cmp(&self, other: &H160) -> std::cmp::Ordering {
        let self_higher = u128::from_be_bytes(self.0[0..16].try_into().unwrap());
        let self_lower = u128::from_be_bytes(self.0[16..20].try_into().unwrap());
        let other_higher = u128::from_be_bytes(other.0[0..16].try_into().unwrap());
        let other_lower = u128::from_be_bytes(other.0[16..20].try_into().unwrap());
        let higher = self_higher.cmp(&other_higher);
        match higher {
            std::cmp::Ordering::Equal => self_lower.cmp(&other_lower),
            _ => higher,
        }
    }
}

impl PartialOrd for H160 {
    fn partial_cmp(&self, other: &H160) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(any(test, test_utilities))]
pub mod tests {
    use super::H256;
    use rand::Rng;

    pub fn generate_random_hash() -> H256 {
        let mut rng = rand::thread_rng();
        let random_bytes: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
        let mut raw_bytes = [0; 32];
        raw_bytes.copy_from_slice(&random_bytes);
        (&raw_bytes).into()
    }
}
