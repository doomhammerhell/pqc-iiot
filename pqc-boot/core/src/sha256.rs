

pub struct Sha256 {
    state: [u32; 8],
    data: [u8; 64],
    len: u64,
}

impl Sha256 {
    pub fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
            ],
            data: [0; 64],
            len: 0,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        let mut i = 0;
        
        while i < data.len() {
            let offset = (self.len as usize) % 64;
            let space = 64 - offset;
            let chunk_len = if (data.len() - i) < space { data.len() - i } else { space };
            
            for j in 0..chunk_len {
                self.data[offset + j] = data[i + j];
            }
            
            self.len += chunk_len as u64;
            i += chunk_len;
            
            if ((self.len as usize) % 64) == 0 {
                self.process_block();
            }
        }
    }

    pub fn finalize(mut self) -> [u8; 32] {
        let len = self.len * 8;
        let offset = (self.len as usize) % 64;
        self.data[offset] = 0x80;
        
        // Pad with zeros
        for i in (offset + 1)..64 {
            self.data[i] = 0;
        }
        
        if offset >= 56 {
            self.process_block();
            for i in 0..64 {
                self.data[i] = 0;
            }
        }
        
        // Append length (big endian)
        self.data[56] = (len >> 56) as u8;
        self.data[57] = (len >> 48) as u8;
        self.data[58] = (len >> 40) as u8;
        self.data[59] = (len >> 32) as u8;
        self.data[60] = (len >> 24) as u8;
        self.data[61] = (len >> 16) as u8;
        self.data[62] = (len >> 8) as u8;
        self.data[63] = (len >> 0) as u8;
        
        self.process_block();
        
        let mut out = [0u8; 32];
        for i in 0..8 {
            out[i * 4 + 0] = (self.state[i] >> 24) as u8;
            out[i * 4 + 1] = (self.state[i] >> 16) as u8;
            out[i * 4 + 2] = (self.state[i] >> 8) as u8;
            out[i * 4 + 3] = (self.state[i] >> 0) as u8;
        }
        out
    }

    fn process_block(&mut self) {
        let mut w = [0u32; 64];
        
        for i in 0..16 {
            w[i] = ((self.data[i * 4] as u32) << 24)
                | ((self.data[i * 4 + 1] as u32) << 16)
                | ((self.data[i * 4 + 2] as u32) << 8)
                | (self.data[i * 4 + 3] as u32);
        }
        
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }
        
        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];
        
        let k: [u32; 64] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        ];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(k[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        
        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}
