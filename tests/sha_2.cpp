#include <gtest/gtest.h>
#include <fstream>
#include <iostream>

#include "../src/sha.h"


// Demonstrate some basic assertions.
TEST(SHA_Test, BasicTest) {
	Sha2 sha2;
	std::ifstream inFile("test_cases.txt");
	std::string inLine, outLine;
	EXPECT_TRUE(inFile.is_open());
	while (std::getline(inFile, inLine)) {
		std::getline(inFile, outLine);
		EXPECT_EQ(outLine, sha2.encodeHash(inLine)) << " for input: " << inLine << ", and output: " << outLine <<
				std::endl;
		std::getline(inFile, outLine); // read the empty line
	}
}

TEST(SHA_Test, DoubleHashTest) {
	Sha2 sha2;
	std::ifstream inFile("test_cases_double.txt");
	std::string inLine, outLine;
	EXPECT_TRUE(inFile.is_open());
	while (std::getline(inFile, inLine)) {
		std::getline(inFile, outLine);

		std::string res = sha2.encodeHexHash(sha2.encodeHexHash(inLine));
		std::string res2 = "";
		for (int i = 0; i * 2 < res.length(); i++) {
			res2 += res.substr(res.length() - 2 - i * 2, 2);
		}

		EXPECT_EQ(outLine, res2) << " for input: " << inLine << ", and output: " << outLine << std::endl;
		std::getline(inFile, outLine); // read the empty line
	}
}

void validateBlocks(std::vector<std::vector<uli> > blocks, std::string hexBlocks) {
	EXPECT_EQ(hexBlocks.length(), blocks.size() * 16 * 9 - 1); // 8 chars + space
	for (int i = 0, j = 0; i < blocks.size(); i++) {
		for (int k = 0; k < blocks[i].size(); k++, j++) {
			std::string blockHex = hexBlocks.substr(j * 9, 8);
			uli expectedBlock = std::stol(blockHex, nullptr, 16);
			EXPECT_EQ(expectedBlock, blocks[i][k]) << " at block " << i << ", " << k << std::endl;
		}
	}
}

TEST(SHA_Test, createBlocks_1) {
	Sha2 sha2;
	std::string text = "abc";
	uli textBytes[text.length()];
	for (int i = 0; i < text.length(); i++) {
		textBytes[i] = static_cast<uli>(text[i]) & static_cast<unsigned long int>(0xff);
	}
	std::vector<std::vector<uli> > res = sha2.createBlocks(textBytes, text.length());
	validateBlocks(
		res,
		"61626380 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000018");
}

TEST(SHA_Test, createBlocks_2) {
	Sha2 sha2;
	std::string text = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
	uli textBytes[text.length()];
	for (int i = 0; i < text.length(); i++) {
		textBytes[i] = static_cast<uli>(text[i]) & static_cast<unsigned long int>(0xff);
	}
	std::vector<std::vector<uli> > res = sha2.createBlocks(textBytes, text.length());
	validateBlocks(
		res,
		"61626364 62636465 63646566 64656667 65666768 66676869 6768696a 68696a6b 696a6b6c 6a6b6c6d 6b6c6d6e 6c6d6e6f 6d6e6f70 6e6f7071 80000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 000001c0");
}
