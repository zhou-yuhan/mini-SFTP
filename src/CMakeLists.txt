aux_source_directory(. DIR_LIB_SRCS)

find_package(OpenSSL REQUIRED)

add_library (sftp ${DIR_LIB_SRCS})

target_include_directories(sftp PUBLIC ../include)

target_link_libraries(sftp OpenSSL::Crypto)