// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! This is an implementaiton of GHASH as used in GCM [1].
//! It is defined as GHASH(H, A, C), where H is a MAC key, A is authenticated data,
//! and C is the ciphertext. GHASH can be used as a keyed MAC, if C is left empty.
//!
//! In order to ensure constant time computation it uses the approach described in [2] section 5.2.
//!
//! [1] - "The Galois/Counter Mode of Operation (GCM)" - David A. McGrew and John Viega
//!       <http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf>
//!
//! [2] - "Faster and Timing-Attack Resistant AES-GCM" - Emilia Käsper and Peter Schwabe
//!       <http://cryptojedi.org/papers/aesbs-20090616.pdf>

use std::ops::BitXor;
use std::mem;
use crate::cryptoutil::copy_memory;

use crate::cryptoutil::{read_u32_be, write_u32_be};
use crate::mac::{Mac, MacResult};
use crate::simd;

// A struct representing an element in GF(2^128)
// x^0 is the msb, while x^127 is the lsb
#[derive(Clone, Copy)]
struct Gf128 { d: simd::u32x4 }

impl Gf128 {
    fn new(a: u32, b: u32, c: u32, d: u32) -> Gf128 {
        Gf128 { d: simd::u32x4(a, b, c, d) }
    }

    fn from_bytes(bytes: &[u8]) -> Gf128 {
        assert!(bytes.len() == 16);
        let d = read_u32_be(&bytes[0..4]);
        let c = read_u32_be(&bytes[4..8]);
        let b = read_u32_be(&bytes[8..12]);
        let a = read_u32_be(&bytes[12..16]);
        Gf128::new(a, b, c, d)
    }

    fn to_bytes(&self) -> [u8; 16] {
        let simd::u32x4(a, b, c, d) = self.d;
        let mut result: [u8; 16] = unsafe { mem::uninitialized() };

        write_u32_be(&mut result[0..4], d);
        write_u32_be(&mut result[4..8], c);
        write_u32_be(&mut result[8..12], b);
        write_u32_be(&mut result[12..16], a);

        result
    }

    // Multiply the element by x modulo x^128
    // This is equivalent to a rightshift in the bit representation
    fn times_x(self) -> Gf128 {
        let simd::u32x4(a, b, c, d) = self.d;
        Gf128::new(a >> 1 | b << 31, b >> 1 | c << 31, c >> 1 |  d << 31, d >> 1)
    }

    // Multiply the element by x modulo x^128 + x^7 + x^2 + x + 1
    // This is equivalent to a rightshift, followed by an XOR iff the lsb was set,
    // in the bit representation
    fn times_x_reduce(self) -> Gf128 {
        let r = Gf128::new(0, 0, 0, 0b1110_0001 << 24);
        self.cond_xor(r, self.times_x())
    }

    // Adds y, and multiplies with h using a precomputed array of the values h * x^0 to h * x^127
    fn add_and_mul(&mut self, y: Gf128, hs: &[Gf128; 128]) {
        *self = *self ^ y;
        let mut x = mem::replace(self, Gf128::new(0, 0, 0, 0));

        for &y in hs.iter().rev() {
            *self = x.cond_xor(y, *self);
            x = x.times_x();
        }
    }

    // This XORs the value of y with x if the LSB of self is set, otherwise y is returned
    fn cond_xor(self, x: Gf128, y: Gf128) -> Gf128 {
        use crate::simd::SimdExt;
        let lsb = simd::u32x4(1, 0, 0, 0);
        let simd::u32x4(m, _, _, _) = (self.d & lsb).simd_eq(lsb);
        let mask = simd::u32x4(m, m, m, m);
        Gf128 { d: (x.d & mask) ^ y.d }
    }
}

impl BitXor for Gf128 {
    type Output = Gf128;

    fn bitxor(self, rhs: Gf128) -> Gf128 {
        Gf128 { d: self.d ^ rhs.d }
    }
}

/// A structure representing the state of a GHASH computation
#[derive(Copy)]
pub struct Ghash {
    hs: [Gf128; 128],
    state: Gf128,
    a_len: usize,
    rest: Option<[u8; 16]>,
    finished: bool
}

impl Clone for Ghash { fn clone(&self) -> Ghash { *self } }

/// A structure representing the state of a GHASH computation, after input for C was provided
#[derive(Copy)]
pub struct GhashWithC {
    hs: [Gf128; 128],
    state: Gf128,
    a_len: usize,
    c_len: usize,
    rest: Option<[u8; 16]>
}

impl Clone for GhashWithC { fn clone(&self) -> GhashWithC { *self } }

fn update(state: &mut Gf128, len: &mut usize, data: &[u8], srest: &mut Option<[u8; 16]>,
          hs: &[Gf128; 128]) {
    let rest_len = *len % 16;
    let data_len = data.len();
    *len += data_len;

    let data = match srest.take() {
        None => data,
        Some(mut rest) => {
            if 16 - rest_len > data_len {
                copy_memory(data, &mut rest[rest_len..]);
                *srest = Some(rest);
                return;
            }

            let (fill, data) = data.split_at(16 - rest_len);
            copy_memory(fill, &mut rest[rest_len..]);
            state.add_and_mul(Gf128::from_bytes(&rest), hs);
            data
        }
    };

    let (data, rest) = data.split_at(data_len - data_len % 16);

    for chunk in data.chunks(16) {
        let x = Gf128::from_bytes(chunk);
        state.add_and_mul(x, hs);
    }

    if !rest.is_empty() {
        let mut tmp = [0; 16];
        copy_memory(rest, &mut tmp);
        *srest = Some(tmp);
    }
}

impl Ghash {
    /// Creates a new GHASH state, with `h` as the key
    #[inline]
    pub fn new(h: &[u8]) -> Ghash {
        assert!(h.len() == 16);
        let mut table: [Gf128; 128] = unsafe { mem::uninitialized() };

        // Precompute values for h * x^0 to h * x^127
        let mut h = Gf128::from_bytes(h);
        for poly in table.iter_mut() {
            *poly = h;
            h = h.times_x_reduce();
        }

        Ghash {
            hs: table,
            state: Gf128::new(0, 0, 0, 0),
            a_len: 0,
            rest: None,
            finished: false
        }
    }

    fn flush(&mut self) {
        for rest in self.rest.take().iter() {
            self.state.add_and_mul(Gf128::from_bytes(rest), &self.hs);
        }
    }

    /// Feeds data for GHASH's A input
    #[inline]
    pub fn input_a(mut self, a: &[u8]) -> Ghash {
        assert!(!self.finished);
        update(&mut self.state, &mut self.a_len, a, &mut self.rest, &self.hs);
        self
    }

    /// Feeds data for GHASH's C input
    #[inline]
    pub fn input_c(mut self, c: &[u8]) -> GhashWithC {
        assert!(!self.finished);
        self.flush();

        let mut c_len = 0;
        update(&mut self.state, &mut c_len, c, &mut self.rest, &self.hs);

        let Ghash { hs, state, a_len, rest, .. } = self;
        GhashWithC {
            hs: hs,
            state: state,
            a_len: a_len,
            c_len: c_len,
            rest: rest
        }
    }

    /// Retrieve the digest result
    #[inline]
    pub fn result(mut self) -> [u8; 16] {
        if !self.finished {
            self.flush();

            let a_len = self.a_len as u64 * 8;
            let lens = Gf128::new(0, 0, a_len as u32, (a_len >> 32) as u32);
            self.state.add_and_mul(lens, &self.hs);

            self.finished = true;
        }

        self.state.to_bytes()
    }
}

impl GhashWithC {
    /// Feeds data for GHASH's C input
    #[inline]
    pub fn input_c(mut self, c: &[u8]) -> GhashWithC {
        update(&mut self.state, &mut self.c_len, c, &mut self.rest, &self.hs);
        self
    }

    /// Retrieve the digest result
    #[inline]
    pub fn result(mut self) -> [u8; 16] {
        for rest in self.rest.take().iter() {
            self.state.add_and_mul(Gf128::from_bytes(rest), &self.hs);
        }

        let a_len = self.a_len as u64 * 8;
        let c_len = self.c_len as u64 * 8;
        let lens = Gf128::new(c_len as u32, (c_len >> 32) as u32,
                              a_len as u32, (a_len >> 32) as u32);
        self.state.add_and_mul(lens, &self.hs);

        self.state.to_bytes()
    }
}

impl Mac for Ghash {
    fn input(&mut self, data: &[u8]) {
        assert!(!self.finished);
        update(&mut self.state, &mut self.a_len, data, &mut self.rest, &self.hs);
    }

    fn reset(&mut self) {
        self.state = Gf128::new(0, 0, 0, 0);
        self.a_len = 0;
        self.rest = None;
        self.finished = false;
    }

    fn result(&mut self) -> MacResult {
        let mut mac = [0u8; 16];
        self.raw_result(&mut mac[..]);
        MacResult::new(&mac[..])
    }

    fn raw_result(&mut self, output: &mut [u8]) {
        assert!(output.len() >= 16);
        if !self.finished {
            self.flush();

            let a_len = self.a_len as u64 * 8;
            let lens = Gf128::new(0, 0, a_len as u32, (a_len >> 32) as u32);
            self.state.add_and_mul(lens, &self.hs);

            self.finished = true;
        }

        copy_memory(&self.state.to_bytes(), output);
    }

    fn output_bytes(&self) -> usize { 16 }
}

#[cfg(test)]
mod test {
    use crate::ghash::Ghash;

    // Test cases from:
    // <http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf>
    static CASES: &'static [(&'static [u8], &'static [u8], &'static [u8], &'static [u8])] = &[
        // Format: (H, A, C, GHASH(H, A, C))

        // Test 1
        (&[0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b,
           0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b, 0x2e],
         &[],
         &[],
         &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),

        // Test 2
        (&[0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b,
           0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b, 0x2e],
         &[],
         &[0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92,
           0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78],
         &[0xf3, 0x8c, 0xbb, 0x1a, 0xd6, 0x92, 0x23, 0xdc,
           0xc3, 0x45, 0x7a, 0xe5, 0xb6, 0xb0, 0xf8, 0x85]),

        // Test 3
        (&[0xb8, 0x3b, 0x53, 0x37, 0x08, 0xbf, 0x53, 0x5d,
           0x0a, 0xa6, 0xe5, 0x29, 0x80, 0xd5, 0x3b, 0x78],
         &[],
         &[0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24, 0x4b, 0x72, 0x21, 0xb7, 0x84, 0xd0,
           0xd4, 0x9c, 0xe3, 0xaa, 0x21, 0x2f, 0x2c, 0x02, 0xa4, 0xe0, 0x35, 0xc1, 0x7e, 0x23,
           0x29, 0xac, 0xa1, 0x2e, 0x21, 0xd5, 0x14, 0xb2, 0x54, 0x66, 0x93, 0x1c, 0x7d, 0x8f,
           0x6a, 0x5a, 0xac, 0x84, 0xaa, 0x05, 0x1b, 0xa3, 0x0b, 0x39, 0x6a, 0x0a, 0xac, 0x97,
           0x3d, 0x58, 0xe0, 0x91, 0x47, 0x3f, 0x59, 0x85],
         &[0x7f, 0x1b, 0x32, 0xb8, 0x1b, 0x82, 0x0d, 0x02,
           0x61, 0x4f, 0x88, 0x95, 0xac, 0x1d, 0x4e, 0xac]),

        // Test 4
        (&[0xb8, 0x3b, 0x53, 0x37, 0x08, 0xbf, 0x53, 0x5d,
           0x0a, 0xa6, 0xe5, 0x29, 0x80, 0xd5, 0x3b, 0x78],
         &[0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed,
           0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2],
         &[0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24, 0x4b, 0x72, 0x21, 0xb7, 0x84, 0xd0,
           0xd4, 0x9c, 0xe3, 0xaa, 0x21, 0x2f, 0x2c, 0x02, 0xa4, 0xe0, 0x35, 0xc1, 0x7e, 0x23,
           0x29, 0xac, 0xa1, 0x2e, 0x21, 0xd5, 0x14, 0xb2, 0x54, 0x66, 0x93, 0x1c, 0x7d, 0x8f,
           0x6a, 0x5a, 0xac, 0x84, 0xaa, 0x05, 0x1b, 0xa3, 0x0b, 0x39, 0x6a, 0x0a, 0xac, 0x97,
           0x3d, 0x58, 0xe0, 0x91],
         &[0x69, 0x8e, 0x57, 0xf7, 0x0e, 0x6e, 0xcc, 0x7f,
           0xd9, 0x46, 0x3b, 0x72, 0x60, 0xa9, 0xae, 0x5f]),

        // Test 5
        (&[0xb8, 0x3b, 0x53, 0x37, 0x08, 0xbf, 0x53, 0x5d,
           0x0a, 0xa6, 0xe5, 0x29, 0x80, 0xd5, 0x3b, 0x78],
         &[0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed,
           0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2],
         &[0x61, 0x35, 0x3b, 0x4c, 0x28, 0x06, 0x93, 0x4a, 0x77, 0x7f, 0xf5, 0x1f, 0xa2, 0x2a,
           0x47, 0x55, 0x69, 0x9b, 0x2a, 0x71, 0x4f, 0xcd, 0xc6, 0xf8, 0x37, 0x66, 0xe5, 0xf9,
           0x7b, 0x6c, 0x74, 0x23, 0x73, 0x80, 0x69, 0x00, 0xe4, 0x9f, 0x24, 0xb2, 0x2b, 0x09,
           0x75, 0x44, 0xd4, 0x89, 0x6b, 0x42, 0x49, 0x89, 0xb5, 0xe1, 0xeb, 0xac, 0x0f, 0x07,
           0xc2, 0x3f, 0x45, 0x98],
         &[0xdf, 0x58, 0x6b, 0xb4, 0xc2, 0x49, 0xb9, 0x2c,
           0xb6, 0x92, 0x28, 0x77, 0xe4, 0x44, 0xd3, 0x7b]),

        // Test 6
        (&[0xb8, 0x3b, 0x53, 0x37, 0x08, 0xbf, 0x53, 0x5d,
           0x0a, 0xa6, 0xe5, 0x29, 0x80, 0xd5, 0x3b, 0x78],
         &[0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed,
           0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2],
         &[0x8c, 0xe2, 0x49, 0x98, 0x62, 0x56, 0x15, 0xb6, 0x03, 0xa0, 0x33, 0xac, 0xa1, 0x3f,
           0xb8, 0x94, 0xbe, 0x91, 0x12, 0xa5, 0xc3, 0xa2, 0x11, 0xa8, 0xba, 0x26, 0x2a, 0x3c,
           0xca, 0x7e, 0x2c, 0xa7, 0x01, 0xe4, 0xa9, 0xa4, 0xfb, 0xa4, 0x3c, 0x90, 0xcc, 0xdc,
           0xb2, 0x81, 0xd4, 0x8c, 0x7c, 0x6f, 0xd6, 0x28, 0x75, 0xd2, 0xac, 0xa4, 0x17, 0x03,
           0x4c, 0x34, 0xae, 0xe5],
         &[0x1c, 0x5a, 0xfe, 0x97, 0x60, 0xd3, 0x93, 0x2f,
           0x3c, 0x9a, 0x87, 0x8a, 0xac, 0x3d, 0xc3, 0xde]),

        // Test 7
        (&[0xaa, 0xe0, 0x69, 0x92, 0xac, 0xbf, 0x52, 0xa3,
           0xe8, 0xf4, 0xa9, 0x6e, 0xc9, 0x30, 0x0b, 0xd7],
         &[],
         &[],
         &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),

        // Test 8
        (&[0xaa, 0xe0, 0x69, 0x92, 0xac, 0xbf, 0x52, 0xa3,
           0xe8, 0xf4, 0xa9, 0x6e, 0xc9, 0x30, 0x0b, 0xd7],
         &[],
         &[0x98, 0xe7, 0x24, 0x7c, 0x07, 0xf0, 0xfe, 0x41,
           0x1c, 0x26, 0x7e, 0x43, 0x84, 0xb0, 0xf6, 0x00],
         &[0xe2, 0xc6, 0x3f, 0x0a, 0xc4, 0x4a, 0xd0, 0xe0,
           0x2e, 0xfa, 0x05, 0xab, 0x67, 0x43, 0xd4, 0xce]),

        // Test 9
        (&[0x46, 0x69, 0x23, 0xec, 0x9a, 0xe6, 0x82, 0x21,
           0x4f, 0x2c, 0x08, 0x2b, 0xad, 0xb3, 0x92, 0x49],
         &[],
         &[0x39, 0x80, 0xca, 0x0b, 0x3c, 0x00, 0xe8, 0x41, 0xeb, 0x06, 0xfa, 0xc4, 0x87, 0x2a,
           0x27, 0x57, 0x85, 0x9e, 0x1c, 0xea, 0xa6, 0xef, 0xd9, 0x84, 0x62, 0x85, 0x93, 0xb4,
           0x0c, 0xa1, 0xe1, 0x9c, 0x7d, 0x77, 0x3d, 0x00, 0xc1, 0x44, 0xc5, 0x25, 0xac, 0x61,
           0x9d, 0x18, 0xc8, 0x4a, 0x3f, 0x47, 0x18, 0xe2, 0x44, 0x8b, 0x2f, 0xe3, 0x24, 0xd9,
           0xcc, 0xda, 0x27, 0x10, 0xac, 0xad, 0xe2, 0x56],
         &[0x51, 0x11, 0x0d, 0x40, 0xf6, 0xc8, 0xff, 0xf0,
           0xeb, 0x1a, 0xe3, 0x34, 0x45, 0xa8, 0x89, 0xf0]),

        // Test 10
        (&[0x46, 0x69, 0x23, 0xec, 0x9a, 0xe6, 0x82, 0x21,
           0x4f, 0x2c, 0x08, 0x2b, 0xad, 0xb3, 0x92, 0x49],
         &[0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed,
           0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2],
         &[0x39, 0x80, 0xca, 0x0b, 0x3c, 0x00, 0xe8, 0x41, 0xeb, 0x06, 0xfa, 0xc4, 0x87, 0x2a,
           0x27, 0x57, 0x85, 0x9e, 0x1c, 0xea, 0xa6, 0xef, 0xd9, 0x84, 0x62, 0x85, 0x93, 0xb4,
           0x0c, 0xa1, 0xe1, 0x9c, 0x7d, 0x77, 0x3d, 0x00, 0xc1, 0x44, 0xc5, 0x25, 0xac, 0x61,
           0x9d, 0x18, 0xc8, 0x4a, 0x3f, 0x47, 0x18, 0xe2, 0x44, 0x8b, 0x2f, 0xe3, 0x24, 0xd9,
           0xcc, 0xda, 0x27, 0x10],
         &[0xed, 0x2c, 0xe3, 0x06, 0x2e, 0x4a, 0x8e, 0xc0,
           0x6d, 0xb8, 0xb4, 0xc4, 0x90, 0xe8, 0xa2, 0x68]),

        // Test 11
        (&[0x46, 0x69, 0x23, 0xec, 0x9a, 0xe6, 0x82, 0x21,
           0x4f, 0x2c, 0x08, 0x2b, 0xad, 0xb3, 0x92, 0x49],
         &[0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed,
           0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2],
         &[0x0f, 0x10, 0xf5, 0x99, 0xae, 0x14, 0xa1, 0x54, 0xed, 0x24, 0xb3, 0x6e, 0x25, 0x32,
           0x4d, 0xb8, 0xc5, 0x66, 0x63, 0x2e, 0xf2, 0xbb, 0xb3, 0x4f, 0x83, 0x47, 0x28, 0x0f,
           0xc4, 0x50, 0x70, 0x57, 0xfd, 0xdc, 0x29, 0xdf, 0x9a, 0x47, 0x1f, 0x75, 0xc6, 0x65,
           0x41, 0xd4, 0xd4, 0xda, 0xd1, 0xc9, 0xe9, 0x3a, 0x19, 0xa5, 0x8e, 0x8b, 0x47, 0x3f,
           0xa0, 0xf0, 0x62, 0xf7],
         &[0x1e, 0x6a, 0x13, 0x38, 0x06, 0x60, 0x78, 0x58,
           0xee, 0x80, 0xea, 0xf2, 0x37, 0x06, 0x40, 0x89]),

        // Test 12
        (&[0x46, 0x69, 0x23, 0xec, 0x9a, 0xe6, 0x82, 0x21,
           0x4f, 0x2c, 0x08, 0x2b, 0xad, 0xb3, 0x92, 0x49],
         &[0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed,
           0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2],
         &[0xd2, 0x7e, 0x88, 0x68, 0x1c, 0xe3, 0x24, 0x3c, 0x48, 0x30, 0x16, 0x5a, 0x8f, 0xdc,
           0xf9, 0xff, 0x1d, 0xe9, 0xa1, 0xd8, 0xe6, 0xb4, 0x47, 0xef, 0x6e, 0xf7, 0xb7, 0x98,
           0x28, 0x66, 0x6e, 0x45, 0x81, 0xe7, 0x90, 0x12, 0xaf, 0x34, 0xdd, 0xd9, 0xe2, 0xf0,
           0x37, 0x58, 0x9b, 0x29, 0x2d, 0xb3, 0xe6, 0x7c, 0x03, 0x67, 0x45, 0xfa, 0x22, 0xe7,
           0xe9, 0xb7, 0x37, 0x3b],
         &[0x82, 0x56, 0x7f, 0xb0, 0xb4, 0xcc, 0x37, 0x18,
           0x01, 0xea, 0xde, 0xc0, 0x05, 0x96, 0x8e, 0x94]),

        // Test 13
        (&[0xdc, 0x95, 0xc0, 0x78, 0xa2, 0x40, 0x89, 0x89,
           0xad, 0x48, 0xa2, 0x14, 0x92, 0x84, 0x20, 0x87],
         &[],
         &[],
         &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),

        // Test 14
        (&[0xdc, 0x95, 0xc0, 0x78, 0xa2, 0x40, 0x89, 0x89,
           0xad, 0x48, 0xa2, 0x14, 0x92, 0x84, 0x20, 0x87],
         &[],
         &[0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e,
           0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3, 0x9d, 0x18],
         &[0x83, 0xde, 0x42, 0x5c, 0x5e, 0xdc, 0x5d, 0x49,
           0x8f, 0x38, 0x2c, 0x44, 0x10, 0x41, 0xca, 0x92]),

        // Test 15
        (&[0xac, 0xbe, 0xf2, 0x05, 0x79, 0xb4, 0xb8, 0xeb,
           0xce, 0x88, 0x9b, 0xac, 0x87, 0x32, 0xda, 0xd7],
         &[],
         &[0x52, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d, 0x07, 0xf4, 0x7f, 0x37, 0xa3, 0x2a, 0x84,
           0x42, 0x7d, 0x64, 0x3a, 0x8c, 0xdc, 0xbf, 0xe5, 0xc0, 0xc9, 0x75, 0x98, 0xa2, 0xbd,
           0x25, 0x55, 0xd1, 0xaa, 0x8c, 0xb0, 0x8e, 0x48, 0x59, 0x0d, 0xbb, 0x3d, 0xa7, 0xb0,
           0x8b, 0x10, 0x56, 0x82, 0x88, 0x38, 0xc5, 0xf6, 0x1e, 0x63, 0x93, 0xba, 0x7a, 0x0a,
           0xbc, 0xc9, 0xf6, 0x62, 0x89, 0x80, 0x15, 0xad],
         &[0x4d, 0xb8, 0x70, 0xd3, 0x7c, 0xb7, 0x5f, 0xcb,
           0x46, 0x09, 0x7c, 0x36, 0x23, 0x0d, 0x16, 0x12]),

        // Test 16
        (&[0xac, 0xbe, 0xf2, 0x05, 0x79, 0xb4, 0xb8, 0xeb,
           0xce, 0x88, 0x9b, 0xac, 0x87, 0x32, 0xda, 0xd7],
         &[0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed,
           0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2],
         &[0x52, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d, 0x07, 0xf4, 0x7f, 0x37, 0xa3, 0x2a, 0x84,
           0x42, 0x7d, 0x64, 0x3a, 0x8c, 0xdc, 0xbf, 0xe5, 0xc0, 0xc9, 0x75, 0x98, 0xa2, 0xbd,
           0x25, 0x55, 0xd1, 0xaa, 0x8c, 0xb0, 0x8e, 0x48, 0x59, 0x0d, 0xbb, 0x3d, 0xa7, 0xb0,
           0x8b, 0x10, 0x56, 0x82, 0x88, 0x38, 0xc5, 0xf6, 0x1e, 0x63, 0x93, 0xba, 0x7a, 0x0a,
           0xbc, 0xc9, 0xf6, 0x62],
         &[0x8b, 0xd0, 0xc4, 0xd8, 0xaa, 0xcd, 0x39, 0x1e,
           0x67, 0xcc, 0xa4, 0x47, 0xe8, 0xc3, 0x8f, 0x65]),

        // Test 17
        (&[0xac, 0xbe, 0xf2, 0x05, 0x79, 0xb4, 0xb8, 0xeb,
           0xce, 0x88, 0x9b, 0xac, 0x87, 0x32, 0xda, 0xd7],
         &[0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed,
           0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2],
         &[0xc3, 0x76, 0x2d, 0xf1, 0xca, 0x78, 0x7d, 0x32, 0xae, 0x47, 0xc1, 0x3b, 0xf1, 0x98,
           0x44, 0xcb, 0xaf, 0x1a, 0xe1, 0x4d, 0x0b, 0x97, 0x6a, 0xfa, 0xc5, 0x2f, 0xf7, 0xd7,
           0x9b, 0xba, 0x9d, 0xe0, 0xfe, 0xb5, 0x82, 0xd3, 0x39, 0x34, 0xa4, 0xf0, 0x95, 0x4c,
           0xc2, 0x36, 0x3b, 0xc7, 0x3f, 0x78, 0x62, 0xac, 0x43, 0x0e, 0x64, 0xab, 0xe4, 0x99,
           0xf4, 0x7c, 0x9b, 0x1f],
         &[0x75, 0xa3, 0x42, 0x88, 0xb8, 0xc6, 0x8f, 0x81,
           0x1c, 0x52, 0xb2, 0xe9, 0xa2, 0xf9, 0x7f, 0x63]),

        // Test 18
        (&[0xac, 0xbe, 0xf2, 0x05, 0x79, 0xb4, 0xb8, 0xeb,
           0xce, 0x88, 0x9b, 0xac, 0x87, 0x32, 0xda, 0xd7],
         &[0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed,
           0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2],
         &[0x5a, 0x8d, 0xef, 0x2f, 0x0c, 0x9e, 0x53, 0xf1, 0xf7, 0x5d, 0x78, 0x53, 0x65, 0x9e,
           0x2a, 0x20, 0xee, 0xb2, 0xb2, 0x2a, 0xaf, 0xde, 0x64, 0x19, 0xa0, 0x58, 0xab, 0x4f,
           0x6f, 0x74, 0x6b, 0xf4, 0x0f, 0xc0, 0xc3, 0xb7, 0x80, 0xf2, 0x44, 0x45, 0x2d, 0xa3,
           0xeb, 0xf1, 0xc5, 0xd8, 0x2c, 0xde, 0xa2, 0x41, 0x89, 0x97, 0x20, 0x0e, 0xf8, 0x2e,
           0x44, 0xae, 0x7e, 0x3f],
         &[0xd5, 0xff, 0xcf, 0x6f, 0xc5, 0xac, 0x4d, 0x69,
           0x72, 0x21, 0x87, 0x42, 0x1a, 0x7f, 0x17, 0x0b])
    ];

    #[test]
    fn hash() {
        for &(h, a, c, g) in CASES.iter() {
            let ghash = Ghash::new(h);
            assert_eq!(&ghash.input_a(a).input_c(c).result()[..], g);
        }
    }

    #[test]
    fn split_input() {
        for &(h, a, c, g) in CASES.iter() {
            let ghash = Ghash::new(h);
            let (a1, a2) = a.split_at(a.len() / 2);
            let (c1, c2) = c.split_at(c.len() / 2);
            assert_eq!(&ghash.input_a(a1)
                            .input_a(a2)
                            .input_c(c1)
                            .input_c(c2)
                            .result()[..], g);
        }
    }
}

#[cfg(all(test, feature = "with-bench"))]
mod bench {
    use test::Bencher;
    use crate::mac::Mac;
    use crate::ghash::Ghash;

    #[bench]
    pub fn ghash_10(bh: & mut Bencher) {
        let mut mac = [0u8; 16];
        let key     = [0u8; 16];
        let bytes   = [1u8; 10];
        bh.iter( || {
            let mut ghash = Ghash::new(&key);
            ghash.input(&bytes);
            ghash.raw_result(&mut mac);
        });
        bh.bytes = bytes.len() as u64;
    }

    #[bench]
    pub fn ghash_1k(bh: & mut Bencher) {
        let mut mac = [0u8; 16];
        let key     = [0u8; 16];
        let bytes   = [1u8; 1024];
        bh.iter( || {
            let mut ghash = Ghash::new(&key);
            ghash.input(&bytes);
            ghash.raw_result(&mut mac);
        });
        bh.bytes = bytes.len() as u64;
    }

    #[bench]
    pub fn ghash_64k(bh: & mut Bencher) {
        let mut mac = [0u8; 16];
        let key     = [0u8; 16];
        let bytes   = [1u8; 65536];
        bh.iter( || {
            let mut ghash = Ghash::new(&key);
            ghash.input(&bytes);
            ghash.raw_result(&mut mac);
        });
        bh.bytes = bytes.len() as u64;
    }
}
