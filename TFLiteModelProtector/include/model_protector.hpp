#ifndef TFLITE_ENCRYPTOR_H_
#define TFLITE_ENCRYPTOR_H_

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <tensorflow/lite/interpreter.h>
#include <tensorflow/lite/kernels/register.h>
#include <tensorflow/lite/model.h>

#include <fstream>
#include <iostream>
#include <memory>
#include <mutex>
#include <vector>

#define ENABLE_LOGGING_LINUX  // Comment out this line to disable linux logging

#ifdef ENABLE_LOGGING_LINUX
#define LOGE(msg) std::cerr << "TFLiteModelProtector: " << msg << std::endl;
#define LOGI(msg) std::cout << "TFLiteModelProtector: " << msg << std::endl;
#endif

class TFLiteModelProtector {
   public:
	static constexpr int kAesKeyLength = 32;  // 256-bit key
	static constexpr int kAesIvLength = 16;	  // 128-bit IV

	TFLiteModelProtector() = default;
	~TFLiteModelProtector() = default;

	bool EncryptFile(const std::string& input_file, const std::string& output_file);
	void DecryptFileToMemory(const std::string& input_file, std::vector<char>& model_buffer);
	std::unique_ptr<tflite::FlatBufferModel> LoadModel(const std::vector<char>& model_data);
	std::unique_ptr<tflite::FlatBufferModel> LoadEncryptedModel(const std::string& model_path);
	void GenerateKeyAndIv(std::vector<uint8_t>& key, std::vector<uint8_t>& iv);
	void SetCustomKeyAndIv(const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv);

   private:
	uint8_t kEncryptionKey[kAesKeyLength] = {};
	uint8_t kEncryptionIv[kAesIvLength] = {};

	static std::mutex mutex_;
	std::vector<char> model_buffer_;  // This is the decrypted model data in memory
};

#endif	// TFLITE_ENCRYPTOR_H_