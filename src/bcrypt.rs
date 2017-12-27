// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

/*!
This public module implements the bcrypt password hash function (slow hash function).
*/

use blowfish::Blowfish;
use cryptoutil::{write_u32_be};
use step_by::RangeExt;

fn setup(cost: u32, salt: &[u8], key: &[u8]) -> Blowfish {
    assert!(cost < 32);
    let mut state = Blowfish::init_state();
    
    state.salted_expand_key(salt, key);
    for _ in 0..1u32 << cost {
        state.expand_key(key);
        state.expand_key(salt);
    }

    state
}

pub fn bcrypt(cost: u32, salt: &[u8], password: &[u8], output: &mut [u8]) {
    assert!(salt.len() == 16);
    assert!(0 < password.len() && password.len() <= 72);
    assert!(output.len() == 24);

    let state = setup(cost, salt, password);
    // OrpheanBeholderScryDoubt
    let mut ctext = [0x4f727068, 0x65616e42, 0x65686f6c, 0x64657253, 0x63727944, 0x6f756274];
    for i in (0..6).step_up(2) {
        for _ in 0..64 {
            let (l, r) = state.encrypt(ctext[i], ctext[i+1]);
            ctext[i] = l;
            ctext[i+1] = r;
        }
        write_u32_be(&mut output[i*4..(i+1)*4], ctext[i]);
        write_u32_be(&mut output[(i+1)*4..(i+2)*4], ctext[i+1]);
    }
}

#[cfg(test)]
mod test {
    use bcrypt::bcrypt;

    struct Test {
        cost: u32,
        salt: Vec<u8>,
        input: Vec<u8>,
        output: Vec<u8>
    }

    // These are $2y$ versions of the test vectors. $2x$ is broken and $2a$ does weird bit-twiddling
    // when it encounters a 0xFF byte.
    fn openwall_test_vectors() -> Vec<Test> {
        vec![
            Test {
                input: vec![0x55u8, 0x2Au8, 0x55u8, 0x00u8],
                cost: 5,
                salt: vec![0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8],
                output: vec![0x1Bu8, 0xB6u8, 0x91u8, 0x43u8, 0xF9u8, 0xA8u8, 0xD3u8, 0x04u8, 0xC8u8, 0xD2u8, 0x3Du8, 0x99u8, 0xABu8, 0x04u8, 0x9Au8, 0x77u8, 0xA6u8, 0x8Eu8, 0x2Cu8, 0xCCu8, 0x74u8, 0x42u8, 0x06u8]
            },
            Test {
                input: vec![0x55u8, 0x2Au8, 0x55u8, 0x2Au8, 0x00u8],
                cost: 5,
                salt: vec![0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8],
                output: vec![0x5Cu8, 0x84u8, 0x35u8, 0x0Bu8, 0xDFu8, 0xBAu8, 0xA9u8, 0x6Au8, 0xC1u8, 0x6Fu8, 0x61u8, 0x5Au8, 0xE7u8, 0x9Fu8, 0x35u8, 0xCFu8, 0xDAu8, 0xCDu8, 0x68u8, 0x2Du8, 0x36u8, 0x9Fu8, 0x23u8]
            },
            Test {
                input: vec![0x55u8, 0x2Au8, 0x55u8, 0x2Au8, 0x55u8, 0x00u8],
                cost: 5,
                salt: vec![0x65u8, 0x96u8, 0x59u8, 0x65u8, 0x96u8, 0x59u8, 0x65u8, 0x96u8, 0x59u8, 0x65u8, 0x96u8, 0x59u8, 0x65u8, 0x96u8, 0x59u8, 0x65u8],
                output: vec![0x09u8, 0xE6u8, 0x73u8, 0xA3u8, 0xF9u8, 0xA5u8, 0x44u8, 0x81u8, 0x8Eu8, 0xB8u8, 0xDDu8, 0x69u8, 0xA8u8, 0xCBu8, 0x28u8, 0xB3u8, 0x2Fu8, 0x6Fu8, 0x7Bu8, 0xE6u8, 0x04u8, 0xCFu8, 0xA7u8]
            },
            Test {
                input: vec![0x30u8, 0x31u8, 0x32u8, 0x33u8, 0x34u8, 0x35u8, 0x36u8, 0x37u8, 0x38u8, 0x39u8, 0x61u8, 0x62u8, 0x63u8, 0x64u8, 0x65u8, 0x66u8, 0x67u8, 0x68u8, 0x69u8, 0x6Au8, 0x6Bu8, 0x6Cu8, 0x6Du8, 0x6Eu8, 0x6Fu8, 0x70u8, 0x71u8, 0x72u8, 0x73u8, 0x74u8, 0x75u8, 0x76u8, 0x77u8, 0x78u8, 0x79u8, 0x7Au8, 0x41u8, 0x42u8, 0x43u8, 0x44u8, 0x45u8, 0x46u8, 0x47u8, 0x48u8, 0x49u8, 0x4Au8, 0x4Bu8, 0x4Cu8, 0x4Du8, 0x4Eu8, 0x4Fu8, 0x50u8, 0x51u8, 0x52u8, 0x53u8, 0x54u8, 0x55u8, 0x56u8, 0x57u8, 0x58u8, 0x59u8, 0x5Au8, 0x30u8, 0x31u8, 0x32u8, 0x33u8, 0x34u8, 0x35u8, 0x36u8, 0x37u8, 0x38u8, 0x39u8],
                cost: 5,
                salt: vec![0x71u8, 0xD7u8, 0x9Fu8, 0x82u8, 0x18u8, 0xA3u8, 0x92u8, 0x59u8, 0xA7u8, 0xA2u8, 0x9Au8, 0xABu8, 0xB2u8, 0xDBu8, 0xAFu8, 0xC3u8],
                output: vec![0xEEu8, 0xEEu8, 0x31u8, 0xF8u8, 0x09u8, 0x19u8, 0x92u8, 0x04u8, 0x25u8, 0x88u8, 0x10u8, 0x02u8, 0xD1u8, 0x40u8, 0xD5u8, 0x55u8, 0xB2u8, 0x8Au8, 0x5Cu8, 0x72u8, 0xE0u8, 0x0Fu8, 0x09u8]
            },
            Test {
                input: vec![0xFFu8, 0xFFu8, 0xA3u8, 0x00u8],
                cost: 5,
                salt: vec![0x05u8, 0x03u8, 0x00u8, 0x85u8, 0xD5u8, 0xEDu8, 0x4Cu8, 0x17u8, 0x6Bu8, 0x2Au8, 0xC3u8, 0xCBu8, 0xEEu8, 0x47u8, 0x29u8, 0x1Cu8],
                output: vec![0x10u8, 0x6Eu8, 0xE0u8, 0x9Cu8, 0x97u8, 0x1Cu8, 0x43u8, 0xA1u8, 0x9Du8, 0x8Au8, 0x25u8, 0xC5u8, 0x95u8, 0xDFu8, 0x91u8, 0xDFu8, 0xF4u8, 0xF0u8, 0x9Bu8, 0x56u8, 0x54u8, 0x3Bu8, 0x98u8]
            },
            Test {
                input: vec![0xA3u8, 0x00u8],
                cost: 5,
                salt: vec![0x05u8, 0x03u8, 0x00u8, 0x85u8, 0xD5u8, 0xEDu8, 0x4Cu8, 0x17u8, 0x6Bu8, 0x2Au8, 0xC3u8, 0xCBu8, 0xEEu8, 0x47u8, 0x29u8, 0x1Cu8],
                output: vec![0x51u8, 0xCFu8, 0x6Eu8, 0x8Du8, 0xDAu8, 0x3Au8, 0x01u8, 0x0Du8, 0x4Cu8, 0xAFu8, 0x11u8, 0xE9u8, 0x67u8, 0x7Au8, 0xD2u8, 0x36u8, 0x84u8, 0x98u8, 0xFFu8, 0xCAu8, 0x96u8, 0x9Cu8, 0x4Bu8]
            },
            Test {
                input: vec![0xFFu8, 0xA3u8, 0x33u8, 0x34u8, 0xFFu8, 0xFFu8, 0xFFu8, 0xA3u8, 0x33u8, 0x34u8, 0x35u8, 0x00u8],
                cost: 5,
                salt: vec![0x05u8, 0x03u8, 0x00u8, 0x85u8, 0xD5u8, 0xEDu8, 0x4Cu8, 0x17u8, 0x6Bu8, 0x2Au8, 0xC3u8, 0xCBu8, 0xEEu8, 0x47u8, 0x29u8, 0x1Cu8],
                output: vec![0xA8u8, 0x00u8, 0x69u8, 0xE3u8, 0xB6u8, 0x57u8, 0x86u8, 0x9Fu8, 0x2Au8, 0x09u8, 0x17u8, 0x16u8, 0xC4u8, 0x98u8, 0x00u8, 0x12u8, 0xE9u8, 0xBAu8, 0xD5u8, 0x38u8, 0x6Eu8, 0x69u8, 0x19u8]
            },
            Test {
                input: vec![0xFFu8, 0xA3u8, 0x33u8, 0x34u8, 0x35u8, 0x00u8],
                cost: 5,
                salt: vec![0x05u8, 0x03u8, 0x00u8, 0x85u8, 0xD5u8, 0xEDu8, 0x4Cu8, 0x17u8, 0x6Bu8, 0x2Au8, 0xC3u8, 0xCBu8, 0xEEu8, 0x47u8, 0x29u8, 0x1Cu8],
                output: vec![0xA5u8, 0x38u8, 0xEFu8, 0xE2u8, 0x70u8, 0x49u8, 0x4Eu8, 0x3Bu8, 0x7Cu8, 0xD6u8, 0x81u8, 0x2Bu8, 0xFFu8, 0x16u8, 0x96u8, 0xC7u8, 0x1Bu8, 0xACu8, 0xD2u8, 0x98u8, 0x67u8, 0x87u8, 0xF8u8]
            },
            Test {
                input: vec![0xA3u8, 0x61u8, 0x62u8, 0x00u8],
                cost: 5,
                salt: vec![0x05u8, 0x03u8, 0x00u8, 0x85u8, 0xD5u8, 0xEDu8, 0x4Cu8, 0x17u8, 0x6Bu8, 0x2Au8, 0xC3u8, 0xCBu8, 0xEEu8, 0x47u8, 0x29u8, 0x1Cu8],
                output: vec![0xF0u8, 0xA8u8, 0x67u8, 0x4Au8, 0x62u8, 0xF4u8, 0xBEu8, 0xA4u8, 0xD7u8, 0x7Bu8, 0x7Du8, 0x30u8, 0x70u8, 0xFBu8, 0xC9u8, 0x86u8, 0x4Cu8, 0x2Cu8, 0x00u8, 0x74u8, 0xE7u8, 0x50u8, 0xA5u8]
            },
            Test {
                input: vec![0xAAu8, 0xAAu8, 0xAAu8, 0xAAu8, 0xAAu8, 0xAAu8, 0xAAu8, 0xAAu8, 0xAAu8, 0xAAu8, 0xAAu8, 0xAAu8, 0xAAu8, 0xAAu8, 0xAAu8, 0xAAu8, 0xAAu8, 0xAAu8, 0xAAu8, 0xAAu8, 0xAAu8, 0xAAu8, 0xAAu8, 0xAAu8, 0xAAu8, 0xAAu8, 0xAAu8, 0xAAu8, 0xAAu8, 0xAAu8, 0xAAu8, 0xAAu8, 0xAAu8, 0xAAu8, 0xAAu8, 0xAAu8, 0xAAu8, 0xAAu8, 0xAAu8, 0xAAu8, 0xAAu8, 0xAAu8, 0xAAu8, 0xAAu8, 0xAAu8, 0xAAu8, 0xAAu8, 0xAAu8, 0xAAu8, 0xAAu8, 0xAAu8, 0xAAu8, 0xAAu8, 0xAAu8, 0xAAu8, 0xAAu8, 0xAAu8, 0xAAu8, 0xAAu8, 0xAAu8, 0xAAu8, 0xAAu8, 0xAAu8, 0xAAu8, 0xAAu8, 0xAAu8, 0xAAu8, 0xAAu8, 0xAAu8, 0xAAu8, 0xAAu8, 0xAAu8],
                cost: 5,
                salt: vec![0x05u8, 0x03u8, 0x00u8, 0x85u8, 0xD5u8, 0xEDu8, 0x4Cu8, 0x17u8, 0x6Bu8, 0x2Au8, 0xC3u8, 0xCBu8, 0xEEu8, 0x47u8, 0x29u8, 0x1Cu8],
                output: vec![0xBBu8, 0x24u8, 0x90u8, 0x2Bu8, 0x59u8, 0x50u8, 0x90u8, 0xBFu8, 0xC8u8, 0x24u8, 0x64u8, 0x70u8, 0x8Cu8, 0x69u8, 0xB1u8, 0xB2u8, 0xD5u8, 0xB4u8, 0xC5u8, 0x88u8, 0xC6u8, 0x3Bu8, 0x3Fu8]
            },
            Test {
                input: vec![0xAAu8, 0x55u8, 0xAAu8, 0x55u8, 0xAAu8, 0x55u8, 0xAAu8, 0x55u8, 0xAAu8, 0x55u8, 0xAAu8, 0x55u8, 0xAAu8, 0x55u8, 0xAAu8, 0x55u8, 0xAAu8, 0x55u8, 0xAAu8, 0x55u8, 0xAAu8, 0x55u8, 0xAAu8, 0x55u8, 0xAAu8, 0x55u8, 0xAAu8, 0x55u8, 0xAAu8, 0x55u8, 0xAAu8, 0x55u8, 0xAAu8, 0x55u8, 0xAAu8, 0x55u8, 0xAAu8, 0x55u8, 0xAAu8, 0x55u8, 0xAAu8, 0x55u8, 0xAAu8, 0x55u8, 0xAAu8, 0x55u8, 0xAAu8, 0x55u8, 0xAAu8, 0x55u8, 0xAAu8, 0x55u8, 0xAAu8, 0x55u8, 0xAAu8, 0x55u8, 0xAAu8, 0x55u8, 0xAAu8, 0x55u8, 0xAAu8, 0x55u8, 0xAAu8, 0x55u8, 0xAAu8, 0x55u8, 0xAAu8, 0x55u8, 0xAAu8, 0x55u8, 0xAAu8, 0x55u8],
                cost: 5,
                salt: vec![0x05u8, 0x03u8, 0x00u8, 0x85u8, 0xD5u8, 0xEDu8, 0x4Cu8, 0x17u8, 0x6Bu8, 0x2Au8, 0xC3u8, 0xCBu8, 0xEEu8, 0x47u8, 0x29u8, 0x1Cu8],
                output: vec![0x4Fu8, 0xFCu8, 0xEDu8, 0x16u8, 0x59u8, 0x34u8, 0x7Bu8, 0x33u8, 0x9Du8, 0x48u8, 0x6Eu8, 0x1Du8, 0xACu8, 0x0Cu8, 0x62u8, 0xB2u8, 0x76u8, 0xABu8, 0x63u8, 0xBCu8, 0xB3u8, 0xE3u8, 0x4Du8]
            },
            Test {
                input: vec![0x55u8, 0xAAu8, 0xFFu8, 0x55u8, 0xAAu8, 0xFFu8, 0x55u8, 0xAAu8, 0xFFu8, 0x55u8, 0xAAu8, 0xFFu8, 0x55u8, 0xAAu8, 0xFFu8, 0x55u8, 0xAAu8, 0xFFu8, 0x55u8, 0xAAu8, 0xFFu8, 0x55u8, 0xAAu8, 0xFFu8, 0x55u8, 0xAAu8, 0xFFu8, 0x55u8, 0xAAu8, 0xFFu8, 0x55u8, 0xAAu8, 0xFFu8, 0x55u8, 0xAAu8, 0xFFu8, 0x55u8, 0xAAu8, 0xFFu8, 0x55u8, 0xAAu8, 0xFFu8, 0x55u8, 0xAAu8, 0xFFu8, 0x55u8, 0xAAu8, 0xFFu8, 0x55u8, 0xAAu8, 0xFFu8, 0x55u8, 0xAAu8, 0xFFu8, 0x55u8, 0xAAu8, 0xFFu8, 0x55u8, 0xAAu8, 0xFFu8, 0x55u8, 0xAAu8, 0xFFu8, 0x55u8, 0xAAu8, 0xFFu8, 0x55u8, 0xAAu8, 0xFFu8, 0x55u8, 0xAAu8, 0xFFu8],
                cost: 5,
                salt: vec![0x05u8, 0x03u8, 0x00u8, 0x85u8, 0xD5u8, 0xEDu8, 0x4Cu8, 0x17u8, 0x6Bu8, 0x2Au8, 0xC3u8, 0xCBu8, 0xEEu8, 0x47u8, 0x29u8, 0x1Cu8],
                output: vec![0xFEu8, 0xF4u8, 0x9Bu8, 0xD5u8, 0xE2u8, 0xE1u8, 0xA3u8, 0x9Cu8, 0x25u8, 0xE0u8, 0xFCu8, 0x4Bu8, 0x06u8, 0x9Eu8, 0xF3u8, 0x9Au8, 0x3Au8, 0xECu8, 0x36u8, 0xD3u8, 0xABu8, 0x60u8, 0x48u8]
            },
            Test {
                input: vec![0x00u8],
                cost: 5,
                salt: vec![0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8, 0x41u8, 0x04u8, 0x10u8],
                output: vec![0xF7u8, 0x02u8, 0x36u8, 0x5Cu8, 0x4Du8, 0x4Au8, 0xE1u8, 0xD5u8, 0x3Du8, 0x97u8, 0xCDu8, 0x28u8, 0xB0u8, 0xB9u8, 0x3Fu8, 0x11u8, 0xF7u8, 0x9Fu8, 0xCEu8, 0x44u8, 0xD5u8, 0x60u8, 0xFDu8]
            }
        ]
    }

    #[test]
    fn test_openwall_test_vectors() {
        let tests = openwall_test_vectors();
        let mut output = [0u8; 24];
        for test in tests.iter() {
            bcrypt(test.cost, &test.salt[..], &test.input[..], &mut output[..]);
            assert!(output[0..23] == test.output[..]);
        }
    }
}

#[cfg(all(test, feature = "with-bench"))]
mod bench {
    use test::Bencher;
    use bcrypt::bcrypt;

    #[bench]
    pub fn bcrypt_16_5(bh: & mut Bencher) {
        let pass = [0u8; 16];
        let salt = [0u8; 16];
        let mut out  = [0u8; 24];
        bh.iter( || {
            bcrypt(5, &salt, &pass, &mut out);
        });
    }
}
