# TFLite Model Encryption & Decryption with AES

## Introduction

This project implements encryption and decryption of TensorFlow Lite (TFLite) models using the Advanced Encryption Standard (AES). The approach enhances the security of machine learning models deployed on edge devices by preventing unauthorized access or tampering. OpenSSL is utilized for cryptographic operations, ensuring robust security and efficiency.

## Dependencies

To run this project, ensure the following dependencies are installed:

- **TensorFlow Lite** (for model inference)
- **OpenSSL** (for AES encryption and decryption)
- **CMake** (for building the project, if applicable)

## Build Instructions

To build the project, follow these steps:

1. Clone the repository:
    ```sh
    git clone https://github.com/yourusername/tflite-model-protector-cpp.git
    cd tflite-model-protector-cpp
    ```

2. Create a build directory and navigate into it:
    ```sh
    mkdir build
    cd build
    ```

3. Run CMake to configure the project:
    ```sh
    cmake ..
    ```

4. Build the project using Make:
    ```sh
    make
    ```

5. The executable will be generated in the `build` directory.

## Running the Application

To run the encryption application, use the following command in the `build` directory:
```sh
./encrypt_model <path_to_tflite_model> 
```
Replace `<path_to_tflite_model>` with the path to your TFLite model file

