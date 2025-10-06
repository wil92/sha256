#include <gtest/gtest.h>
#include <fstream>
#include <iostream>
#include <chrono>

#include "../src/sha.h"

TEST(SHA_Test, PerformanceTest) {
	Sha2 sha;
	const std::string input =
			"00000020980714d8c5502491b53e51ae97c6705274e33da1ad6001000000000000000000a3cd3101bdb2b2f4f96e9057e46152ecfa8a105bf59dfd61294f324d7ae1cd3808ffe268b4dd011727abd0c7";

	const int iterations = 100;
	long long duration = 0;

	for (int i = 0; i < iterations; i++) {
		const auto start = std::chrono::high_resolution_clock::now();
		const std::string hash = sha.encodeHexHash(input);
		const auto end = std::chrono::high_resolution_clock::now();
		duration += std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
		ASSERT_FALSE(hash.empty());
	}

	duration /= iterations;
	std::cout << "SHA256 encodeHash took " << duration << " microseconds." << std::endl;
	ASSERT_TRUE(duration < 15);
}

TEST(SHA_Test, HashTest) {
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
