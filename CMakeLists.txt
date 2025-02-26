
cmake_minimum_required(VERSION 3.22.1)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Werror=return-type")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fpic")

project("TFLiteModelProtector")

add_subdirectory(TFLiteModelProtector)

# ######################### for tflite model encryption
add_executable(
        encrypt_model

        encrypt_model.cpp
)

target_include_directories(
        encrypt_model

        PRIVATE

        include
)

target_link_libraries(
        encrypt_model

        TFLiteModelProtector
        tflite
)