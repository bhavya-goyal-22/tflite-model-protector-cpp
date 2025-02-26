find_package(OpenSSL REQUIRED)

include_directories(include
${OpenCV_INCLUDE_DIRS}
)

set (TFLiteModelProtector_INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/include PARENT_SCOPE)

set(SOURCE_FILES
    src/model_protector.cpp
)

set(HEADER_FILES
    include/model_protector.hpp)

add_library(TFLiteModelProtector SHARED  ${SOURCE_FILES} ${HEADER_FILES})

target_link_libraries(TFLiteModelProtector
        tflite
        OpenSSL::Crypto
        )

target_include_directories(TFLiteModelProtector PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
