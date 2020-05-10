#[macro_use]
extern crate hex_literal;

#[cfg(test)]
#[macro_use]
extern crate time_test;

pub mod bit_vec;
pub mod bloom_filter;
pub mod hash;
pub mod key_pair;
pub mod merkle_mountain_range;
pub mod merkle_tree;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
