#include <filesystem>
#include <fstream>
#include <iostream>
#include <vector>

#include "TFLiteModelProtector/include/model_protector.hpp"

namespace fs = std::filesystem;

int main(int argc, char* argv[]) {
	TFLiteModelProtector model_protector;
	if (argc != 2) {
		std::cerr << "Usage: " << argv[0] << " <tflite_model_file>" << std::endl;
		return 1;
	}

	std::string input_file = argv[1];
	std::string filename = input_file.substr(0, input_file.find_last_of("."));
	std::string encrypted_file = filename + ".enc";

	std::vector<uint8_t> key(TFLiteModelProtector::kAesKeyLength);
	std::vector<uint8_t> iv(TFLiteModelProtector::kAesIvLength);

	model_protector.GenerateKeyAndIv(key, iv);

	if (!model_protector.EncryptFile(input_file, encrypted_file)) {
		std::cerr << "Encryption failed!" << std::endl;
		return 1;
	}

	std::cout << "Encryption successful!" << std::endl;
	std::cout << "Encrypted model saved as: " << encrypted_file << std::endl;

	return 0;
}
