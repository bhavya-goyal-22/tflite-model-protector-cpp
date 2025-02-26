#include "model_protector.hpp"

std::mutex TFLiteModelProtector::mutex_;

/**
 * @brief Encrypts the contents of an input file and writes the encrypted data to an output file.
 *
 * This function uses AES-256-CBC encryption to encrypt the contents of the specified input file.
 * The encrypted data is then written to the specified output file.
 *
 * @param input_file The path to the input file to be encrypted.
 * @param output_file The path to the output file where the encrypted data will be written.
 * @return true if the encryption and file writing were successful, false otherwise.
 */
bool TFLiteModelProtector::EncryptFile(const std::string& input_file,
									   const std::string& output_file) {
	std::ifstream in(input_file, std::ios::binary);
	std::ofstream out(output_file, std::ios::binary);

	if (!in || !out) {
		LOGE("File open error!");
		return false;
	}

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, kEncryptionKey, kEncryptionIv);

	std::vector<uint8_t> buffer(4096);
	std::vector<uint8_t> cipher_buffer(4096 + EVP_MAX_BLOCK_LENGTH);
	int out_len = 0;

	while (in.read(reinterpret_cast<char*>(buffer.data()), buffer.size()) || in.gcount()) {
		EVP_EncryptUpdate(ctx, cipher_buffer.data(), &out_len, buffer.data(), in.gcount());
		out.write(reinterpret_cast<char*>(cipher_buffer.data()), out_len);
	}

	EVP_EncryptFinal_ex(ctx, cipher_buffer.data(), &out_len);
	out.write(reinterpret_cast<char*>(cipher_buffer.data()), out_len);

	EVP_CIPHER_CTX_free(ctx);
	return true;
}

/**
 * @brief Decrypts an encrypted file and loads its contents into memory.
 *
 * This function reads an encrypted file specified by `input_file`, decrypts its contents
 * using AES-256-CBC, and stores the decrypted data in the provided `model_data` vector.
 *
 * @param input_file The path to the encrypted input file.
 * @param model_data A reference to a vector where the decrypted data will be stored.
 *
 * @note The function uses a fixed encryption key and initialization vector (IV) defined
 *       by `kEncryptionKey` and `kEncryptionIv` respectively.
 * @note If the file cannot be opened, an error message is logged and the function returns.
 */
void TFLiteModelProtector::DecryptFileToMemory(const std::string& input_file,
											   std::vector<char>& model_data) {
	std::ifstream in(input_file, std::ios::binary);

	if (!in) {
		LOGE("File open error!");
		return;
	}

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, kEncryptionKey, kEncryptionIv);

	std::vector<uint8_t> buffer(4096);
	std::vector<uint8_t> plain_buffer(4096 + EVP_MAX_BLOCK_LENGTH);
	int out_len = 0;

	while (in.read(reinterpret_cast<char*>(buffer.data()), buffer.size()) || in.gcount()) {
		EVP_DecryptUpdate(ctx, plain_buffer.data(), &out_len, buffer.data(), in.gcount());
		model_data.insert(model_data.end(), plain_buffer.begin(), plain_buffer.begin() + out_len);
	}

	EVP_DecryptFinal_ex(ctx, plain_buffer.data(), &out_len);

	EVP_CIPHER_CTX_free(ctx);
	in.close();
}

/**
 * @brief Loads a TensorFlow Lite model from the provided model data.
 *
 * This function takes a vector of characters representing the model data
 * and attempts to build a TensorFlow Lite FlatBufferModel from it.
 *
 * @param model_data A vector of characters containing the model data.
 * @return A unique pointer to the loaded TensorFlow Lite FlatBufferModel.
 */
std::unique_ptr<tflite::FlatBufferModel> TFLiteModelProtector::LoadModel(
	const std::vector<char>& model_data) {
	return tflite::FlatBufferModel::BuildFromBuffer(model_data.data(), model_data.size());
}

/**
 * @brief Loads an encrypted TensorFlow Lite model from the specified file path.
 *
 * This function decrypts the model file into memory and then loads the model
 * from the decrypted data. It uses a mutex to ensure thread safety.
 *
 * @param model_path The file path to the encrypted model.
 * @return A unique pointer to the loaded TensorFlow Lite model, or nullptr if an exception occurs.
 */
std::unique_ptr<tflite::FlatBufferModel> TFLiteModelProtector::LoadEncryptedModel(
	const std::string& model_path) {
	std::lock_guard<std::mutex> lock(mutex_);
	try {
		DecryptFileToMemory(model_path, model_buffer_);
		return LoadModel(model_buffer_);
	} catch (const std::exception& e) {
		LOGE("Exception caught: " + std::string(e.what()));
		return nullptr;
	}
}

/**
 * @brief Generates a random AES key and initialization vector (IV).
 *
 * This function uses the OpenSSL RAND_bytes function to generate a random AES key and IV.
 * The generated key and IV are stored in the provided vectors.
 *
 * @param key A vector to store the generated AES key. The size of the vector should be
 * kAesKeyLength.
 * @param iv A vector to store the generated AES IV. The size of the vector should be kAesIvLength.
 *
 * @throws std::runtime_error if the key or IV generation fails.
 */
void TFLiteModelProtector::GenerateKeyAndIv(std::vector<uint8_t>& key, std::vector<uint8_t>& iv) {
	if (!RAND_bytes(key.data(), kAesKeyLength) || !RAND_bytes(iv.data(), kAesIvLength)) {
		throw std::runtime_error("Failed to generate key or IV");
	}

	std::ostringstream key_stream;
	key_stream << "Generated Key: ";
	for (const auto& byte : key) {
		key_stream << std::hex << static_cast<int>(byte) << " ";
	}
	LOGI(key_stream.str());

	std::ostringstream iv_stream;
	iv_stream << "Generated IV: ";
	for (const auto& byte : iv) {
		iv_stream << std::hex << static_cast<int>(byte) << " ";
	}
	LOGI(iv_stream.str());
}

/**
 * @brief Sets a custom encryption key and initialization vector (IV) for the TFLite model
 * protector.
 *
 * This function allows the user to specify a custom AES encryption key and IV to be used for
 * encrypting and decrypting the TFLite model. The key and IV must have lengths equal to the
 * predefined constants kAesKeyLength and kAesIvLength, respectively.
 *
 * @param key A vector of bytes representing the custom AES encryption key. The size of the vector
 *            must be equal to kAesKeyLength.
 * @param iv  A vector of bytes representing the custom AES initialization vector. The size of the
 *            vector must be equal to kAesIvLength.
 *
 * @throws std::invalid_argument If the size of the key or IV does not match the required length.
 */
void TFLiteModelProtector::SetCustomKeyAndIv(const std::vector<uint8_t>& key,
											 const std::vector<uint8_t>& iv) {
	if (key.size() != kAesKeyLength || iv.size() != kAesIvLength) {
		throw std::invalid_argument("Invalid key or IV length");
	}

	std::copy(key.begin(), key.end(), kEncryptionKey);
	std::copy(iv.begin(), iv.end(), kEncryptionIv);

	std::ostringstream key_stream;
	key_stream << "Custom Key set: ";
	for (const auto& byte : key) {
		key_stream << std::hex << static_cast<int>(byte) << " ";
	}
	LOGI(key_stream.str());

	std::ostringstream iv_stream;
	iv_stream << "Custom IV set: ";
	for (const auto& byte : iv) {
		iv_stream << std::hex << static_cast<int>(byte) << " ";
	}
	LOGI(iv_stream.str());
}