cmake_minimum_required(VERSION 3.16)

project(specus_server_c C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
find_package(ZLIB REQUIRED)
find_package(SQLite3 REQUIRED)

add_library(specus_c_core
    src/admin_http.c
    src/crypto.c
    src/json.c
    src/protocol.c
    src/security.c
    src/storage.c
)
target_include_directories(specus_c_core PUBLIC src)
target_link_libraries(specus_c_core PUBLIC ZLIB::ZLIB SQLite::SQLite3)
target_compile_options(specus_c_core PRIVATE -Wall -Wextra -Wpedantic)

add_executable(specus-server-c src/main.c)
target_link_libraries(specus-server-c PRIVATE specus_c_core)
target_compile_options(specus-server-c PRIVATE -Wall -Wextra -Wpedantic)

enable_testing()
add_executable(specus_c_admin_http_tests tests/admin_http_tests.c)
target_link_libraries(specus_c_admin_http_tests PRIVATE specus_c_core)
target_compile_options(specus_c_admin_http_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME admin_http_tests COMMAND specus_c_admin_http_tests)

add_executable(specus_c_crypto_tests tests/crypto_tests.c)
target_link_libraries(specus_c_crypto_tests PRIVATE specus_c_core)
target_compile_options(specus_c_crypto_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME crypto_tests COMMAND specus_c_crypto_tests)

add_executable(specus_c_json_tests tests/json_tests.c)
target_link_libraries(specus_c_json_tests PRIVATE specus_c_core)
target_compile_options(specus_c_json_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME json_tests COMMAND specus_c_json_tests)

add_executable(specus_c_protocol_fixture_tests tests/protocol_fixture_tests.c)
target_link_libraries(specus_c_protocol_fixture_tests PRIVATE specus_c_core)
target_compile_options(specus_c_protocol_fixture_tests PRIVATE -Wall -Wextra -Wpedantic)
target_compile_definitions(specus_c_protocol_fixture_tests PRIVATE
    ST_FIXTURE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/../../../protocol/test-vectors/control-v2/frames/")
add_test(NAME protocol_fixture_tests COMMAND specus_c_protocol_fixture_tests)

add_executable(specus_c_security_tests tests/security_tests.c)
target_link_libraries(specus_c_security_tests PRIVATE specus_c_core)
target_compile_options(specus_c_security_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME security_tests COMMAND specus_c_security_tests)

add_executable(specus_c_storage_tests tests/storage_tests.c)
target_link_libraries(specus_c_storage_tests PRIVATE specus_c_core)
target_compile_options(specus_c_storage_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME storage_tests COMMAND specus_c_storage_tests)
