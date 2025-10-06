#ifndef SHA_H
#define SHA_H

#include <complex>
#include <string>

#define uli unsigned long int
#define BLOCK_SIZE 16

class Sha2 {
public:
	std::string encodeHash(const std::string &text) {
		uli textBytes[text.length()];
		for (int i = 0; i < text.length(); i++) {
			textBytes[i] = static_cast<uli>(text[i]) & static_cast<unsigned long int>(0xff);
		}
		return encodeHash(textBytes, text.length());
	}

	std::string encodeHexHash(const std::string &hexText) {
		uli textBytes[hexText.length() / 2];
		for (int i = 0; i * 2 < hexText.length(); i++) {
			textBytes[i] = std::stol(hexText.substr(i * 2, 2), nullptr, 16);
		}
		return encodeHash(textBytes, hexText.length() / 2);
	}

	std::string encodeHash(const uli *text, const size_t length) {
		const uli fixedValues[64] = {
			0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
			0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
			0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
			0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
			0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
			0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
			0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
			0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
		};

		const int l = static_cast<int>(length) * 8;
		int block_size = 0, k;
		do {
			block_size += 512;
			k = block_size - (l + 64 + 1);
		} while (k < 0);
		const int numberOfSubBlocks = (l + 1 + k + 64) / 32;
		uli blocks[numberOfSubBlocks];
		uli w[64];
		createBlocks(text, l, blocks, numberOfSubBlocks);

		uli h1 = 0x6a09e667, h2 = 0xbb67ae85, h3 = 0x3c6ef372, h4 = 0xa54ff53a,
				h5 = 0x510e527f, h6 = 0x9b05688c, h7 = 0x1f83d9ab, h8 = 0x5be0cd19;
		for (int i = 0, size = numberOfSubBlocks / BLOCK_SIZE; i < size; i++) {
			uli a = h1, b = h2, c = h3, d = h4, e = h5, f = h6, g = h7, h = h8;

			precalculateW(w, i, blocks);

			for (int j = 0; j < 64; j++) {
				const uli t1 = (h + bigSigma1(e) + chFunction(e, f, g) + fixedValues[j] + w[j]) & 0xffffffff;
				const uli t2 = (bigSigma0(a) + majFunction(a, b, c)) & 0xffffffff;
				h = g;
				g = f;
				f = e;
				e = (d + t1) & 0xffffffff;
				d = c;
				c = b;
				b = a;
				a = (t1 + t2) & 0xffffffff;
			}

			h1 = (a + h1) & 0xffffffff;
			h2 = (b + h2) & 0xffffffff;
			h3 = (c + h3) & 0xffffffff;
			h4 = (d + h4) & 0xffffffff;
			h5 = (e + h5) & 0xffffffff;
			h6 = (f + h6) & 0xffffffff;
			h7 = (g + h7) & 0xffffffff;
			h8 = (h + h8) & 0xffffffff;
		}

		std::string hash;
		for (const uli h: {h1, h2, h3, h4, h5, h6, h7, h8}) {
			for (int i = 0; i < 8; i++) {
				hash += toHexChar((h >> (28 - i * 4)) & 0xf);
			}
		}
		return hash;
	}

	inline char toHexChar(const uli i) {
		return (i < 10) ? '0' + i : 'a' + (i - 10);
	}

	inline void precalculateW(uli *w, const int i, const uli *blocks) {
		for (int j = 0; j < 64; j++) {
			if (j < 16) {
				w[j] = blocks[i * BLOCK_SIZE + j];
			} else {
				w[j] = (smallSigma1(w[j - 2]) + w[j - 7]
				        + smallSigma0(w[j - 15]) + w[j - 16]) & 0xffffffff;
			}
		}
	}

	inline uli chFunction(const uli x, const uli y, const uli z) {
		return ((x & y) ^ (~x & z)) & 0xffffffff;
	}

	inline uli majFunction(const uli x, const uli y, const uli z) {
		return ((x & y) ^ (x & z) ^ (y & z)) & 0xffffffff;
	}

	inline uli bigSigma0(const uli x) {
		return (rotRight(x, 2) ^ rotRight(x, 13) ^ rotRight(x, 22)) & 0xffffffff;
	}

	inline uli bigSigma1(const uli x) {
		return (rotRight(x, 6) ^ rotRight(x, 11) ^ rotRight(x, 25)) & 0xffffffff;
	}

	inline uli smallSigma0(const uli x) {
		return (rotRight(x, 7) ^ rotRight(x, 18) ^ (x >> 3)) & 0xffffffff;
	}

	inline uli smallSigma1(const uli x) {
		return (rotRight(x, 17) ^ rotRight(x, 19) ^ (x >> 10)) & 0xffffffff;
	}

	inline uli rotRight(const uli x, const unsigned int y) {
		return (x >> y | x << (32 - y)) & 0xffffffff;
	}

	inline void createBlocks(const uli *msg, const uli l, uli *blocks, const int numberOfSubBlocks) {
		for (int i = 0; i < numberOfSubBlocks; i++) {
			blocks[i] = 0;
		}

		// copy the original message in the blocks
		for (int i = 0; i < numberOfSubBlocks && i * 4 * 8 <= l; i++) {
			for (int j = 0; j < 4; j++) {
				if (const int index = i * 4 + j; index * 8 < l) {
					blocks[i] |= (msg[index] & static_cast<uli>(0xff)) << ((3 - j) * 8);
				} else if (index * 8 >= l) {
					blocks[i] |= static_cast<uli>(0x80) << ((3 - j) * 8);
					break;
				}
			}
		}

		// last block is the length of the original message
		blocks[numberOfSubBlocks - 1] = l;
	}
};

#endif //SHA_H
