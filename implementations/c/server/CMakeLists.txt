cmake_minimum_required(VERSION 3.16)

project(specus_server_c C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
find_package(ZLIB REQUIRED)
find_package(SQLite3 REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)
find_path(HIREDIS_INCLUDE_DIR hiredis/hiredis.h REQUIRED)
find_library(HIREDIS_LIBRARY hiredis REQUIRED)
find_path(UTF8PROC_INCLUDE_DIR utf8proc.h REQUIRED)
find_library(UTF8PROC_LIBRARY utf8proc REQUIRED)

add_library(specus_c_core
    src/admin_http.c
    src/client_address.c
    src/client_package.c
    src/crypto.c
    src/decompression_limits.c
    src/elasticsearch_traffic.c
    src/github_release.c
    src/http_client.c
    src/json.c
    src/login_rate_limiter.c
    src/media_capture.c
    src/object_storage.c
    src/password_hash.c
    src/peer_egress.c
    src/peer_mesh.c
    src/protocol.c
    src/public_coordination.c
    src/public_discovery.c
    src/public_room.c
    src/registration.c
    src/security.c
    src/security_baseline.c
    src/storage.c
    src/stun_turn.c
    src/tls_transport.c
    src/turn_auth.c
)
target_include_directories(specus_c_core PUBLIC src PRIVATE ${HIREDIS_INCLUDE_DIR} ${UTF8PROC_INCLUDE_DIR})
target_link_libraries(specus_c_core PUBLIC ZLIB::ZLIB SQLite::SQLite3 OpenSSL::SSL OpenSSL::Crypto CURL::libcurl ${HIREDIS_LIBRARY} ${UTF8PROC_LIBRARY})
target_compile_options(specus_c_core PRIVATE -Wall -Wextra -Wpedantic)

add_executable(specus-server-c src/main.c)
target_link_libraries(specus-server-c PRIVATE specus_c_core)
target_compile_options(specus-server-c PRIVATE -Wall -Wextra -Wpedantic)

enable_testing()
add_executable(specus_c_admin_http_tests tests/admin_http_tests.c)
target_link_libraries(specus_c_admin_http_tests PRIVATE specus_c_core)
target_compile_options(specus_c_admin_http_tests PRIVATE -Wall -Wextra -Wpedantic)
target_compile_definitions(specus_c_admin_http_tests PRIVATE
    ST_APPLICATION_FIXTURE_FILE="${CMAKE_CURRENT_SOURCE_DIR}/../../../protocol/test-vectors/application-protocol-v2.json")
add_test(NAME admin_http_tests COMMAND specus_c_admin_http_tests)

add_executable(specus_c_github_release_tests tests/github_release_tests.c)
target_link_libraries(specus_c_github_release_tests PRIVATE specus_c_core)
target_compile_options(specus_c_github_release_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME github_release_tests COMMAND specus_c_github_release_tests)

add_executable(specus_c_client_address_tests tests/client_address_tests.c)
target_link_libraries(specus_c_client_address_tests PRIVATE specus_c_core)
target_compile_options(specus_c_client_address_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME client_address_tests COMMAND specus_c_client_address_tests)

add_executable(specus_c_crypto_tests tests/crypto_tests.c)
target_link_libraries(specus_c_crypto_tests PRIVATE specus_c_core)
target_compile_options(specus_c_crypto_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME crypto_tests COMMAND specus_c_crypto_tests)

add_executable(specus_c_decompression_limits_tests tests/decompression_limits_tests.c)
target_link_libraries(specus_c_decompression_limits_tests PRIVATE specus_c_core)
target_compile_options(specus_c_decompression_limits_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME decompression_limits_tests COMMAND specus_c_decompression_limits_tests)

add_executable(specus_c_elasticsearch_traffic_tests tests/elasticsearch_traffic_tests.c)
target_link_libraries(specus_c_elasticsearch_traffic_tests PRIVATE specus_c_core)
target_compile_options(specus_c_elasticsearch_traffic_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME elasticsearch_traffic_tests
    COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/elasticsearch_traffic_test.sh
                 $<TARGET_FILE:specus_c_elasticsearch_traffic_tests>)
set_tests_properties(elasticsearch_traffic_tests PROPERTIES TIMEOUT 45)

add_executable(specus_c_json_tests tests/json_tests.c)
target_link_libraries(specus_c_json_tests PRIVATE specus_c_core)
target_compile_options(specus_c_json_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME json_tests COMMAND specus_c_json_tests)

add_executable(specus_c_http_client_tests tests/http_client_tests.c)
target_link_libraries(specus_c_http_client_tests PRIVATE specus_c_core)
target_compile_options(specus_c_http_client_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME http_client_tests COMMAND specus_c_http_client_tests)

add_executable(specus_c_login_rate_limiter_tests tests/login_rate_limiter_tests.c)
target_link_libraries(specus_c_login_rate_limiter_tests PRIVATE specus_c_core)
target_compile_options(specus_c_login_rate_limiter_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME login_rate_limiter_tests COMMAND specus_c_login_rate_limiter_tests)

add_executable(specus_c_object_storage_tests tests/object_storage_tests.c)
target_link_libraries(specus_c_object_storage_tests PRIVATE specus_c_core)
target_compile_options(specus_c_object_storage_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME object_storage_tests COMMAND specus_c_object_storage_tests)
add_test(NAME object_storage_e2e
    COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/object_storage_e2e.sh
                 $<TARGET_FILE:specus-server-c>)
set_tests_properties(object_storage_e2e PROPERTIES TIMEOUT 45)

add_executable(specus_c_media_capture_tests tests/media_capture_tests.c)
target_link_libraries(specus_c_media_capture_tests PRIVATE specus_c_core)
target_compile_options(specus_c_media_capture_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME media_capture_tests
    COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/media_capture_test.sh
                 $<TARGET_FILE:specus_c_media_capture_tests>)
set_tests_properties(media_capture_tests PROPERTIES TIMEOUT 45)

add_executable(specus_c_password_hash_tests tests/password_hash_tests.c)
target_link_libraries(specus_c_password_hash_tests PRIVATE specus_c_core)
target_compile_options(specus_c_password_hash_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME password_hash_tests COMMAND specus_c_password_hash_tests)

add_executable(specus_c_peer_egress_tests tests/peer_egress_tests.c)
target_link_libraries(specus_c_peer_egress_tests PRIVATE specus_c_core)
target_compile_options(specus_c_peer_egress_tests PRIVATE -Wall -Wextra -Wpedantic)
target_compile_definitions(specus_c_peer_egress_tests PRIVATE
    ST_EGRESS_VECTOR_DIR="${CMAKE_CURRENT_SOURCE_DIR}/../../../protocol/test-vectors/")
add_test(NAME peer_egress_tests COMMAND specus_c_peer_egress_tests)

add_executable(specus_c_peer_mesh_tests tests/peer_mesh_tests.c)
target_link_libraries(specus_c_peer_mesh_tests PRIVATE specus_c_core)
target_compile_options(specus_c_peer_mesh_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME peer_mesh_tests COMMAND specus_c_peer_mesh_tests)

add_executable(specus_c_public_coordination_tests tests/public_coordination_tests.c)
target_link_libraries(specus_c_public_coordination_tests PRIVATE specus_c_core)
target_compile_options(specus_c_public_coordination_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME public_coordination_tests
    COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/public_coordination_test.sh
                 $<TARGET_FILE:specus_c_public_coordination_tests>)
add_test(NAME public_discovery_cluster_e2e
    COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/public_discovery_cluster_e2e.sh
                 $<TARGET_FILE:specus-server-c>)
set_tests_properties(public_discovery_cluster_e2e PROPERTIES TIMEOUT 45)

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

add_executable(specus_c_security_baseline_tests tests/security_baseline_tests.c)
target_link_libraries(specus_c_security_baseline_tests PRIVATE specus_c_core)
target_compile_options(specus_c_security_baseline_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME security_baseline_tests COMMAND specus_c_security_baseline_tests)

add_executable(specus_c_storage_tests tests/storage_tests.c)
target_link_libraries(specus_c_storage_tests PRIVATE specus_c_core)
target_compile_options(specus_c_storage_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME storage_tests COMMAND specus_c_storage_tests)

add_executable(specus_c_stun_turn_tests tests/stun_turn_tests.c)
target_link_libraries(specus_c_stun_turn_tests PRIVATE specus_c_core)
target_compile_options(specus_c_stun_turn_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME stun_turn_tests COMMAND specus_c_stun_turn_tests)

add_executable(specus_c_tls_transport_tests tests/tls_transport_tests.c)
target_link_libraries(specus_c_tls_transport_tests PRIVATE specus_c_core)
target_compile_options(specus_c_tls_transport_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME tls_transport_tests COMMAND specus_c_tls_transport_tests)
