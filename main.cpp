#include <iostream>

#include "src/sha.h"

// TIP To <b>Run</b> code, press <shortcut actionId="Run"/> or click the <icon src="AllIcons.Actions.Execute"/> icon in the gutter.
int main() {
	Sha2 sha2;

	std::string res = sha2.encodeHash("abc");

	std::cout << res << std::endl;

	return 0;
}