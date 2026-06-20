cmake_minimum_required(VERSION 3.16)

project(shuai_tunnel_server_c C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
find_package(ZLIB REQUIRED)

add_library(shuai_tunnel_c_core
    src/crypto.c
    src/json.c
    src/protocol.c
)
target_include_directories(shuai_tunnel_c_core PUBLIC src)
target_link_libraries(shuai_tunnel_c_core PUBLIC ZLIB::ZLIB)
target_compile_options(shuai_tunnel_c_core PRIVATE -Wall -Wextra -Wpedantic)

add_executable(shuai-tunnel-server-c src/main.c)
target_link_libraries(shuai-tunnel-server-c PRIVATE shuai_tunnel_c_core)
target_compile_options(shuai-tunnel-server-c PRIVATE -Wall -Wextra -Wpedantic)

enable_testing()
add_executable(shuai_tunnel_c_crypto_tests tests/crypto_tests.c)
target_link_libraries(shuai_tunnel_c_crypto_tests PRIVATE shuai_tunnel_c_core)
target_compile_options(shuai_tunnel_c_crypto_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME crypto_tests COMMAND shuai_tunnel_c_crypto_tests)

add_executable(shuai_tunnel_c_json_tests tests/json_tests.c)
target_link_libraries(shuai_tunnel_c_json_tests PRIVATE shuai_tunnel_c_core)
target_compile_options(shuai_tunnel_c_json_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME json_tests COMMAND shuai_tunnel_c_json_tests)

add_executable(shuai_tunnel_c_protocol_fixture_tests tests/protocol_fixture_tests.c)
target_link_libraries(shuai_tunnel_c_protocol_fixture_tests PRIVATE shuai_tunnel_c_core)
target_compile_options(shuai_tunnel_c_protocol_fixture_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME protocol_fixture_tests COMMAND shuai_tunnel_c_protocol_fixture_tests)
