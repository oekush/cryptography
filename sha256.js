class SHA256 {
    constructor() {
        this.k = new Uint32Array([
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        ]);

        // Initial hash values (first 32 bits of the fractional parts of the square roots of the first 8 primes)
        this.h = new Uint32Array([
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        ]);
    }

    // Rotate right
    rotr(n, x) {
        return (x >>> n) | (x << (32 - n));
    }

    // Choice
    ch(x, y, z) {
        return (x & y) ^ (~x & z);
    }

    // Majority
    maj(x, y, z) {
        return (x & y) ^ (x & z) ^ (y & z);
    }

    // Sigma 0
    sig0(x) {
        return this.rotr(2, x) ^ this.rotr(13, x) ^ this.rotr(22, x);
    }

    // Sigma 1
    sig1(x) {
        return this.rotr(6, x) ^ this.rotr(11, x) ^ this.rotr(25, x);
    }

    // Gamma 0
    gam0(x) {
        return this.rotr(7, x) ^ this.rotr(18, x) ^ (x >>> 3);
    }

    // Gamma 1
    gam1(x) {
        return this.rotr(17, x) ^ this.rotr(19, x) ^ (x >>> 10);
    }

    // Process a 512-bit block
    processBlock(block) {
        const w = new Uint32Array(64);
        
        // Copy block into first 16 words of w
        for (let i = 0; i < 16; i++) {
            w[i] = (block[i * 4] << 24) | (block[i * 4 + 1] << 16) |
                   (block[i * 4 + 2] << 8) | block[i * 4 + 3];
        }

        // Extend the first 16 words into the remaining 48 words
        for (let i = 16; i < 64; i++) {
            w[i] = (this.gam1(w[i - 2]) + w[i - 7] + this.gam0(w[i - 15]) + w[i - 16]) >>> 0;
        }

        // Initialize working variables
        let [a, b, c, d, e, f, g, h] = this.h;

        // Main loop
        for (let i = 0; i < 64; i++) {
            const t1 = (h + this.sig1(e) + this.ch(e, f, g) + this.k[i] + w[i]) >>> 0;
            const t2 = (this.sig0(a) + this.maj(a, b, c)) >>> 0;
            
            h = g;
            g = f;
            f = e;
            e = (d + t1) >>> 0;
            d = c;
            c = b;
            b = a;
            a = (t1 + t2) >>> 0;
        }

        // Update hash values
        this.h[0] = (this.h[0] + a) >>> 0;
        this.h[1] = (this.h[1] + b) >>> 0;
        this.h[2] = (this.h[2] + c) >>> 0;
        this.h[3] = (this.h[3] + d) >>> 0;
        this.h[4] = (this.h[4] + e) >>> 0;
        this.h[5] = (this.h[5] + f) >>> 0;
        this.h[6] = (this.h[6] + g) >>> 0;
        this.h[7] = (this.h[7] + h) >>> 0;
    }

    // Main hash function
    hash(message) {
        // Convert string to byte array if necessary
        const data = typeof message === 'string' ? 
            new TextEncoder().encode(message) : 
            new Uint8Array(message);

        // Calculate padding length
        const bitLength = data.length * 8;
        const padLength = (((data.length + 8) >>> 6) + 1) << 6;
        const padded = new Uint8Array(padLength);

        // Copy message to padded array
        padded.set(data);

        // Append 1 bit
        padded[data.length] = 0x80;

        // Append length as 64-bit big-endian integer
        const view = new DataView(padded.buffer);
        view.setUint32(padLength - 8, Math.floor(bitLength / 0x100000000), false);
        view.setUint32(padLength - 4, bitLength & 0xffffffff, false);

        // Process blocks
        for (let i = 0; i < padLength; i += 64) {
            this.processBlock(padded.subarray(i, i + 64));
        }

        // Convert hash to hex string
        return Array.from(this.h)
            .map(h => h.toString(16).padStart(8, '0'))
            .join('');
    }
}

// Utility function to hash a string
function hashString(str) {
    const sha256 = new SHA256();
    return sha256.hash(str);
}

// Example usage:
const testString = "suckkaa ";
const hashedValue = hashString(testString);
console.log(`Original string: ${testString}`);
console.log(`SHA-256 hash: ${hashedValue}`);