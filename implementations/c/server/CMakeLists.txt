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
# Optional: hiredis' TLS layer for rediss:// and rediss-sentinel:// (hiredis 1.0 or later; part of
# libhiredis-dev on Ubuntu 24.04, absent from the hiredis 0.14 of Ubuntu 22.04 and Debian 12).
# Without it those URIs fail startup with a message and the TLS tests are not registered.
find_library(HIREDIS_SSL_LIBRARY hiredis_ssl)
find_path(UTF8PROC_INCLUDE_DIR utf8proc.h REQUIRED)
find_library(UTF8PROC_LIBRARY utf8proc REQUIRED)

add_library(specus_c_core
    src/admin_http.c
    src/client_address.c
    src/client_auth_nonce.c
    src/client_package.c
    src/connectivity_check.c
    src/crypto.c
    src/decompression_limits.c
    src/elasticsearch_traffic.c
    src/github_release.c
    src/http_client.c
    src/http_share.c
    src/instant.c
    src/instant_storage.c
    src/java_uri.c
    src/json.c
    src/login_rate_limiter.c
    src/media_capture.c
    src/metrics.c
    src/object_storage.c
    src/oidc.c
    src/password_hash.c
    src/peer_egress.c
    src/peer_mesh.c
    src/product_metrics.c
    src/protocol.c
    src/public_coordination.c
    src/public_discovery.c
    src/public_room.c
    src/redis_uri.c
    src/registration.c
    src/security.c
    src/security_baseline.c
    src/storage.c
    src/stream_tombstones.c
    src/stun_turn.c
    src/tls_transport.c
    src/traffic_capture.c
    src/traffic_usage.c
    src/turn_auth.c
    src/upstream_browser_headers.c
    src/unicode_java21.c
    src/url_decode.c
    src/workbench.c
    src/websocket_ticket.c
)
target_include_directories(specus_c_core PUBLIC src PRIVATE ${HIREDIS_INCLUDE_DIR} ${UTF8PROC_INCLUDE_DIR})
target_link_libraries(specus_c_core PUBLIC ZLIB::ZLIB SQLite::SQLite3 OpenSSL::SSL OpenSSL::Crypto CURL::libcurl ${HIREDIS_LIBRARY} ${UTF8PROC_LIBRARY})
if(HIREDIS_SSL_LIBRARY)
    message(STATUS "hiredis_ssl found: rediss:// and rediss-sentinel:// are supported")
    target_compile_definitions(specus_c_core PRIVATE ST_HAVE_HIREDIS_SSL)
    target_link_libraries(specus_c_core PUBLIC ${HIREDIS_SSL_LIBRARY})
else()
    message(STATUS "hiredis_ssl not found: rediss:// and rediss-sentinel:// fail startup")
endif()
target_compile_options(specus_c_core PRIVATE -Wall -Wextra -Wpedantic)

add_executable(specus_c_unicode_java21_tests tests/unicode_java21_tests.c)
target_link_libraries(specus_c_unicode_java21_tests PRIVATE specus_c_core)
target_compile_options(specus_c_unicode_java21_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME unicode_java21_tests COMMAND specus_c_unicode_java21_tests
    "${CMAKE_CURRENT_SOURCE_DIR}/../../../protocol/test-vectors/java21-root-case-v1.json")

# The java.net.URI port behind the client download link URL checks.
add_executable(specus_c_java_uri_tests tests/java_uri_tests.c)
target_link_libraries(specus_c_java_uri_tests PRIVATE specus_c_core)
target_compile_options(specus_c_java_uri_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME java_uri_tests COMMAND specus_c_java_uri_tests
    "${CMAKE_CURRENT_SOURCE_DIR}/../../../protocol/test-vectors/client-download-link-validation-v1.json")

# libbrotlidec is optional: with it, Content-Encoding br is decoded as Java's org.brotli:dec does
# (traffic detail previews and display, media manifests); without it a br body stays as stored.
# libbrotlienc, when present too, lets the tests compress their own br fixtures.
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(BROTLIDEC QUIET libbrotlidec)
    pkg_check_modules(BROTLIENC QUIET libbrotlienc)
endif()
if(BROTLIDEC_FOUND)
    message(STATUS "libbrotlidec found: Content-Encoding br is decoded")
    target_compile_definitions(specus_c_core PUBLIC ST_HAVE_BROTLI)
    target_include_directories(specus_c_core PUBLIC ${BROTLIDEC_INCLUDE_DIRS})
    target_link_libraries(specus_c_core PUBLIC ${BROTLIDEC_LINK_LIBRARIES})
else()
    message(STATUS "libbrotlidec not found: Content-Encoding br is not decoded")
endif()

add_executable(specus-server-c src/main.c)
target_link_libraries(specus-server-c PRIVATE specus_c_core)
target_compile_options(specus-server-c PRIVATE -Wall -Wextra -Wpedantic)

enable_testing()
add_executable(specus_c_url_decode_tests tests/url_decode_tests.c)
target_link_libraries(specus_c_url_decode_tests PRIVATE specus_c_core)
target_compile_options(specus_c_url_decode_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME url_decode_tests COMMAND specus_c_url_decode_tests)

add_executable(specus_c_redis_uri_tests tests/redis_uri_tests.c)
target_link_libraries(specus_c_redis_uri_tests PRIVATE specus_c_core)
target_compile_options(specus_c_redis_uri_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME redis_uri_tests COMMAND specus_c_redis_uri_tests)
add_executable(specus_c_connectivity_lifetime_tests tests/connectivity_lifetime_tests.c)
target_link_libraries(specus_c_connectivity_lifetime_tests PRIVATE specus_c_core pthread)
target_link_options(specus_c_connectivity_lifetime_tests PRIVATE "-Wl,--wrap=free" "-Wl,--wrap=st_connectivity_checker_new" "-Wl,--wrap=st_connectivity_handle")
target_compile_options(specus_c_connectivity_lifetime_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME connectivity_lifetime_tests COMMAND specus_c_connectivity_lifetime_tests)
set_tests_properties(connectivity_lifetime_tests PROPERTIES TIMEOUT 30)
add_executable(specus_c_connectivity_setter_tests tests/connectivity_setter_tests.c)
target_link_libraries(specus_c_connectivity_setter_tests PRIVATE specus_c_core)
target_compile_options(specus_c_connectivity_setter_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME connectivity_setter_tests COMMAND specus_c_connectivity_setter_tests)
set_tests_properties(connectivity_setter_tests PROPERTIES TIMEOUT 30)
add_executable(specus_c_admin_http_tests tests/admin_http_tests.c)
target_link_libraries(specus_c_admin_http_tests PRIVATE specus_c_core)
target_compile_options(specus_c_admin_http_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME admin_http_tests COMMAND specus_c_admin_http_tests)

add_executable(specus_c_direct_websocket_tests tests/direct_websocket_tests.c)
target_link_libraries(specus_c_direct_websocket_tests PRIVATE specus_c_core)
target_compile_options(specus_c_direct_websocket_tests PRIVATE -Wall -Wextra -Wpedantic)
target_compile_definitions(specus_c_direct_websocket_tests PRIVATE
    ST_APPLICATION_FIXTURE_FILE="${CMAKE_CURRENT_SOURCE_DIR}/../../../protocol/test-vectors/application-protocol-v2.json")
add_test(NAME direct_websocket_tests COMMAND specus_c_direct_websocket_tests)
set_tests_properties(direct_websocket_tests PROPERTIES TIMEOUT 120)

add_executable(specus_c_github_release_tests tests/github_release_tests.c)
target_link_libraries(specus_c_github_release_tests PRIVATE specus_c_core)
target_compile_options(specus_c_github_release_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME github_release_tests COMMAND specus_c_github_release_tests)

# The client catalogue and hosted packages against the Java ClientDownloadLink*/ClientPackage* tests.
add_executable(specus_c_client_package_tests tests/client_package_tests.c)
target_link_libraries(specus_c_client_package_tests PRIVATE specus_c_core)
target_compile_options(specus_c_client_package_tests PRIVATE -Wall -Wextra -Wpedantic)
target_compile_definitions(specus_c_client_package_tests PRIVATE
    ST_DOWNLOAD_LINK_VECTOR_FILE="${CMAKE_CURRENT_SOURCE_DIR}/../../../protocol/test-vectors/client-download-link-validation-v1.json")
add_test(NAME client_package_tests COMMAND specus_c_client_package_tests)

add_executable(specus_c_client_address_tests tests/client_address_tests.c)
target_link_libraries(specus_c_client_address_tests PRIVATE specus_c_core)
target_compile_options(specus_c_client_address_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME client_address_tests COMMAND specus_c_client_address_tests)

add_executable(specus_c_semantic_version_tests tests/semantic_version_tests.c)
target_link_libraries(specus_c_semantic_version_tests PRIVATE specus_c_core)
target_compile_options(specus_c_semantic_version_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME semantic_version_tests COMMAND specus_c_semantic_version_tests)

add_executable(specus_c_traffic_capture_tests tests/traffic_capture_tests.c)
target_link_libraries(specus_c_traffic_capture_tests PRIVATE specus_c_core)
target_compile_options(specus_c_traffic_capture_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME traffic_capture_tests COMMAND specus_c_traffic_capture_tests)

add_executable(specus_c_turnstile_verifier_tests tests/turnstile_verifier_tests.c)
target_link_libraries(specus_c_turnstile_verifier_tests PRIVATE specus_c_core)
target_compile_options(specus_c_turnstile_verifier_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME turnstile_verifier_tests COMMAND specus_c_turnstile_verifier_tests)

add_executable(specus_c_upstream_browser_headers_tests tests/upstream_browser_headers_tests.c)
target_link_libraries(specus_c_upstream_browser_headers_tests PRIVATE specus_c_core)
target_compile_options(specus_c_upstream_browser_headers_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME upstream_browser_headers_tests COMMAND specus_c_upstream_browser_headers_tests)

add_executable(specus_c_client_auth_nonce_tests tests/client_auth_nonce_tests.c)
target_link_libraries(specus_c_client_auth_nonce_tests PRIVATE specus_c_core)
target_compile_options(specus_c_client_auth_nonce_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME client_auth_nonce_tests COMMAND specus_c_client_auth_nonce_tests)

add_executable(specus_c_connectivity_check_tests tests/connectivity_check_tests.c tests/connectivity_test_clock.c)
target_link_libraries(specus_c_connectivity_check_tests PRIVATE specus_c_core)
target_compile_options(specus_c_connectivity_check_tests PRIVATE -Wall -Wextra -Wpedantic)
target_compile_definitions(specus_c_connectivity_check_tests PRIVATE
    ST_CONNECTIVITY_VECTOR_DIR="${CMAKE_CURRENT_SOURCE_DIR}/../../../protocol/test-vectors/")
add_test(NAME connectivity_check_tests COMMAND specus_c_connectivity_check_tests)

add_executable(specus_c_connectivity_http_vector_tests tests/connectivity_http_vector_tests.c tests/connectivity_http_resource_tests.c tests/connectivity_test_clock.c)
target_link_libraries(specus_c_connectivity_http_vector_tests PRIVATE specus_c_core pthread)
target_compile_options(specus_c_connectivity_http_vector_tests PRIVATE -Wall -Wextra -Wpedantic)
target_compile_definitions(specus_c_connectivity_http_vector_tests PRIVATE
    ST_CONNECTIVITY_VECTOR_DIR="${CMAKE_CURRENT_SOURCE_DIR}/../../../protocol/test-vectors/")
add_test(NAME connectivity_http_vector_tests COMMAND specus_c_connectivity_http_vector_tests)
set_tests_properties(connectivity_http_vector_tests PROPERTIES TIMEOUT 120)

add_executable(specus_c_connectivity_resource_wire_tests tests/connectivity_resource_wire_tests.c tests/server_harness.c)
target_link_libraries(specus_c_connectivity_resource_wire_tests PRIVATE specus_c_core pthread)
target_compile_options(specus_c_connectivity_resource_wire_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME connectivity_resource_wire_tests COMMAND specus_c_connectivity_resource_wire_tests $<TARGET_FILE:specus-server-c>)
set_tests_properties(connectivity_resource_wire_tests PROPERTIES TIMEOUT 120)

add_executable(specus_c_connectivity_rate_http_tests tests/connectivity_rate_http_tests.c tests/connectivity_test_clock.c)
target_link_libraries(specus_c_connectivity_rate_http_tests PRIVATE specus_c_core pthread)
target_compile_options(specus_c_connectivity_rate_http_tests PRIVATE -Wall -Wextra -Wpedantic)
target_compile_definitions(specus_c_connectivity_rate_http_tests PRIVATE
    ST_CONNECTIVITY_VECTOR_DIR="${CMAKE_CURRENT_SOURCE_DIR}/../../../protocol/test-vectors/")
add_test(NAME connectivity_rate_http_tests COMMAND specus_c_connectivity_rate_http_tests)
set_tests_properties(connectivity_rate_http_tests PROPERTIES TIMEOUT 120)

add_executable(specus_c_crypto_tests tests/crypto_tests.c)
target_link_libraries(specus_c_crypto_tests PRIVATE specus_c_core)
target_compile_options(specus_c_crypto_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME crypto_tests COMMAND specus_c_crypto_tests)

add_executable(specus_c_decompression_limits_tests tests/decompression_limits_tests.c)
target_link_libraries(specus_c_decompression_limits_tests PRIVATE specus_c_core)
if(BROTLIDEC_FOUND AND BROTLIENC_FOUND)
    target_compile_definitions(specus_c_decompression_limits_tests PRIVATE ST_HAVE_BROTLI_ENCODER)
    target_include_directories(specus_c_decompression_limits_tests PRIVATE ${BROTLIENC_INCLUDE_DIRS})
    target_link_libraries(specus_c_decompression_limits_tests PRIVATE ${BROTLIENC_LINK_LIBRARIES})
endif()
target_compile_options(specus_c_decompression_limits_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME decompression_limits_tests COMMAND specus_c_decompression_limits_tests)

add_executable(specus_c_elasticsearch_traffic_tests tests/elasticsearch_traffic_tests.c)
target_link_libraries(specus_c_elasticsearch_traffic_tests PRIVATE specus_c_core)
target_compile_options(specus_c_elasticsearch_traffic_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME elasticsearch_traffic_tests
    COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/elasticsearch_traffic_test.sh
                 $<TARGET_FILE:specus_c_elasticsearch_traffic_tests>)
set_tests_properties(elasticsearch_traffic_tests PROPERTIES TIMEOUT 45)

# The traffic detail API against Java's semantics: search over Elasticsearch through an in-process
# admin listener, TCP capture from a real server process through the write queue, and the stream
# contract and large pages on SQLite. Runs against the same fake Elasticsearch.
add_executable(specus_c_traffic_detail_api_tests tests/traffic_detail_api_tests.c tests/server_harness.c)
target_link_libraries(specus_c_traffic_detail_api_tests PRIVATE specus_c_core)
target_compile_options(specus_c_traffic_detail_api_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME traffic_detail_api_tests
    COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/elasticsearch_traffic_test.sh
                 $<TARGET_FILE:specus_c_traffic_detail_api_tests> $<TARGET_FILE:specus-server-c>)
set_tests_properties(traffic_detail_api_tests PROPERTIES TIMEOUT 180)

# protocol/spec/client-messages.md on a real server process (admin to client, client to every
# session of an administrator, a disabled sender) and a failed write on an in-process listener.
add_executable(specus_c_client_messages_tests tests/client_messages_tests.c tests/server_harness.c)
target_link_libraries(specus_c_client_messages_tests PRIVATE specus_c_core)
target_compile_options(specus_c_client_messages_tests PRIVATE -Wall -Wextra -Wpedantic)
target_compile_definitions(specus_c_client_messages_tests PRIVATE
    ST_MANAGEMENT_ACCOUNTS_VECTOR_FILE="${CMAKE_CURRENT_SOURCE_DIR}/../../../protocol/test-vectors/management-accounts-v1.json")
add_test(NAME client_messages_tests
    COMMAND specus_c_client_messages_tests $<TARGET_FILE:specus-server-c>)
set_tests_properties(client_messages_tests PROPERTIES TIMEOUT 120)

# Slow management WebSocket readers against Java's Tomcat send timeout (20 s per 8 KiB): a stalled
# socket holds up no other socket, control session or revocation, and is closed after the timeout,
# once 4096 frames wait behind it or past 64 MiB queued in all; a slow but steady reader is kept; a
# browser's CLOSE goes ahead of the backlog; admin-to-client writes in flight per socket. A real
# server and in process.
add_executable(specus_c_management_ws_backpressure_tests tests/management_ws_backpressure_tests.c tests/server_harness.c)
target_link_libraries(specus_c_management_ws_backpressure_tests PRIVATE specus_c_core)
target_compile_options(specus_c_management_ws_backpressure_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME management_ws_backpressure_tests
    COMMAND specus_c_management_ws_backpressure_tests $<TARGET_FILE:specus-server-c>)
set_tests_properties(management_ws_backpressure_tests PROPERTIES TIMEOUT 150)

# A browser that stops reading a route WebSocket, on a real server: the data connection keeps
# serving heartbeats, HTTP, TCP and another WebSocket meanwhile, the stalled stream gets no credit,
# and it is closed with RST 31 after Java's Tomcat send timeout (20 s), not before.
add_executable(specus_c_direct_websocket_backpressure_tests tests/direct_websocket_backpressure_tests.c tests/server_harness.c)
target_link_libraries(specus_c_direct_websocket_backpressure_tests PRIVATE specus_c_core)
target_compile_options(specus_c_direct_websocket_backpressure_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME direct_websocket_backpressure_tests
    COMMAND specus_c_direct_websocket_backpressure_tests $<TARGET_FILE:specus-server-c>)
set_tests_properties(direct_websocket_backpressure_tests PROPERTIES TIMEOUT 150)

# Management lists with more rows than the arrays C used to read them into, over real HTTP.
add_executable(specus_c_management_lists_tests tests/management_lists_tests.c tests/server_harness.c)
target_link_libraries(specus_c_management_lists_tests PRIVATE specus_c_core)
target_compile_options(specus_c_management_lists_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME management_lists_tests COMMAND specus_c_management_lists_tests)
set_tests_properties(management_lists_tests PROPERTIES TIMEOUT 180)

# Registration, /me, credentials, mappings, name availability, initialize and traffic usage against Java.
add_executable(specus_c_management_crud_tests tests/management_crud_tests.c tests/server_harness.c)
target_link_libraries(specus_c_management_crud_tests PRIVATE specus_c_core)
target_compile_options(specus_c_management_crud_tests PRIVATE -Wall -Wextra -Wpedantic)
target_compile_definitions(specus_c_management_crud_tests PRIVATE
    ST_MAILBOX_VECTOR_FILE="${CMAKE_CURRENT_SOURCE_DIR}/../../../protocol/test-vectors/registration-mailbox-forms-v1.json"
    ST_EMAIL_MASK_VECTOR_FILE="${CMAKE_CURRENT_SOURCE_DIR}/../../../protocol/test-vectors/registration-email-mask-v1.json"
    ST_EMAIL_NUL_VECTOR_FILE="${CMAKE_CURRENT_SOURCE_DIR}/../../../protocol/test-vectors/registration-email-nul-v1.json")
add_test(NAME management_crud_tests COMMAND specus_c_management_crud_tests)

# The Peer Mesh / Egress management endpoints, Spring-converted parameters, mapping create, times.
add_executable(specus_c_peer_mesh_api_tests tests/peer_mesh_api_tests.c tests/server_harness.c)
target_link_libraries(specus_c_peer_mesh_api_tests PRIVATE specus_c_core)
target_compile_options(specus_c_peer_mesh_api_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME peer_mesh_api_tests COMMAND specus_c_peer_mesh_api_tests)
set_tests_properties(peer_mesh_api_tests PROPERTIES TIMEOUT 120)
set_tests_properties(management_crud_tests PROPERTIES TIMEOUT 120)

# Java OverviewService on a real server process: clients, logins and public connection counters.
add_executable(specus_c_management_overview_tests tests/management_overview_tests.c tests/server_harness.c)
target_link_libraries(specus_c_management_overview_tests PRIVATE specus_c_core)
target_compile_options(specus_c_management_overview_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME management_overview_tests
    COMMAND specus_c_management_overview_tests $<TARGET_FILE:specus-server-c>)
set_tests_properties(management_overview_tests PROPERTIES TIMEOUT 120)

add_executable(specus_c_http_share_tests tests/http_share_tests.c)
target_link_libraries(specus_c_http_share_tests PRIVATE specus_c_core)
target_compile_options(specus_c_http_share_tests PRIVATE -Wall -Wextra -Wpedantic)
target_compile_definitions(specus_c_http_share_tests PRIVATE
    ST_SHARE_VECTOR_FILE="${CMAKE_CURRENT_SOURCE_DIR}/../../../protocol/test-vectors/temporary-http-share-v1.json")
add_test(NAME http_share_tests COMMAND specus_c_http_share_tests)
set_tests_properties(http_share_tests PROPERTIES TIMEOUT 120)

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
target_compile_definitions(specus_c_object_storage_tests PRIVATE
    ST_TRANSFER_VECTOR_DIR="${CMAKE_CURRENT_SOURCE_DIR}/../../../protocol/test-vectors/")
add_test(NAME object_storage_tests COMMAND specus_c_object_storage_tests)
add_test(NAME object_storage_e2e
    COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/object_storage_e2e.sh
                 $<TARGET_FILE:specus-server-c>)
set_tests_properties(object_storage_e2e PROPERTIES TIMEOUT 45
    ENVIRONMENT "SPECUS_TEST_OSS_START_DELAY_SECONDS=0.5")

add_executable(specus_c_media_capture_tests tests/media_capture_tests.c)
target_link_libraries(specus_c_media_capture_tests PRIVATE specus_c_core)
target_compile_options(specus_c_media_capture_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME media_capture_tests
    COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/media_capture_test.sh
                 $<TARGET_FILE:specus_c_media_capture_tests>)
set_tests_properties(media_capture_tests PROPERTIES TIMEOUT 45)

add_executable(specus_c_oidc_tests tests/oidc_tests.c)
target_link_libraries(specus_c_oidc_tests PRIVATE specus_c_core)
target_compile_options(specus_c_oidc_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME oidc_tests COMMAND specus_c_oidc_tests)
set_tests_properties(oidc_tests PROPERTIES TIMEOUT 120)

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
target_compile_definitions(specus_c_peer_mesh_tests PRIVATE
    ST_EGRESS_VECTOR_DIR="${CMAKE_CURRENT_SOURCE_DIR}/../../../protocol/test-vectors/")
add_test(NAME peer_mesh_tests COMMAND specus_c_peer_mesh_tests)

# Peer Mesh control messages (egress-report) over a real control connection of a real server process.
add_executable(specus_c_peer_mesh_e2e_tests tests/peer_mesh_e2e_tests.c tests/server_harness.c)
target_link_libraries(specus_c_peer_mesh_e2e_tests PRIVATE specus_c_core)
target_compile_options(specus_c_peer_mesh_e2e_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME peer_mesh_e2e_tests
    COMMAND specus_c_peer_mesh_e2e_tests $<TARGET_FILE:specus-server-c>)
set_tests_properties(peer_mesh_e2e_tests PROPERTIES TIMEOUT 120)

add_executable(specus_c_public_coordination_tests tests/public_coordination_tests.c)
target_link_libraries(specus_c_public_coordination_tests PRIVATE specus_c_core)
target_compile_options(specus_c_public_coordination_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME public_coordination_tests
    COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/public_coordination_test.sh
                 $<TARGET_FILE:specus_c_public_coordination_tests>)
# redis-sentinel:// and rediss-sentinel://: master discovery and SENTINEL FAILOVER with a master,
# a replica and one Sentinel (distinct port ranges, so the two may run in parallel).
add_executable(specus_c_public_coordination_sentinel_tests tests/public_coordination_sentinel_tests.c)
target_link_libraries(specus_c_public_coordination_sentinel_tests PRIVATE specus_c_core)
target_compile_options(specus_c_public_coordination_sentinel_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME public_coordination_sentinel_tests
    COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/public_coordination_sentinel_test.sh
                 $<TARGET_FILE:specus_c_public_coordination_sentinel_tests> plain)
if(HIREDIS_SSL_LIBRARY)
    # The same suite over rediss:// against a TLS port with a throwaway CA, plus the verifyPeer probes.
    add_test(NAME public_coordination_tls_tests
        COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/public_coordination_tls_test.sh
                     $<TARGET_FILE:specus_c_public_coordination_tests>)
    add_test(NAME public_coordination_sentinel_tls_tests
        COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/public_coordination_sentinel_test.sh
                     $<TARGET_FILE:specus_c_public_coordination_sentinel_tests> tls)
endif()
add_test(NAME public_discovery_cluster_e2e
    COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/public_discovery_cluster_e2e.sh
                 $<TARGET_FILE:specus-server-c>)
# About 6 s locally; the margin lets a failing step's own timeout (up to 20 s) print the logs.
set_tests_properties(public_discovery_cluster_e2e PROPERTIES TIMEOUT 90)
add_test(NAME management_cluster_e2e
    COMMAND python3 ${CMAKE_CURRENT_SOURCE_DIR}/scripts/management_cluster_e2e.py
                    $<TARGET_FILE:specus-server-c>)
set_tests_properties(management_cluster_e2e PROPERTIES TIMEOUT 90)
# The STCE envelope and the cluster identifiers against protocol/test-vectors/public-transfer-cluster-v2.json
# (Java PublicTransferClusterFrameTests and PublicTransferCoordinationServiceTests).
add_executable(specus_c_public_cluster_codec_tests tests/public_cluster_codec_tests.c)
target_link_libraries(specus_c_public_cluster_codec_tests PRIVATE specus_c_core)
target_compile_options(specus_c_public_cluster_codec_tests PRIVATE -Wall -Wextra -Wpedantic)
target_compile_definitions(specus_c_public_cluster_codec_tests PRIVATE
    ST_CLUSTER_VECTOR_FILE="${CMAKE_CURRENT_SOURCE_DIR}/../../../protocol/test-vectors/public-transfer-cluster-v2.json")
add_test(NAME public_cluster_codec_tests COMMAND specus_c_public_cluster_codec_tests)
# Discovery, the STWR2 relay, WebSocket tickets and public rooms over loopback HTTP and WebSocket
# (Java PublicTransferDiscoveryWebSocketHandlerTests, PublicTransferRelayFrameTests,
# WebSocketTicketServiceTests, PublicTransferRoomResourceTests, PublicTransferRoomServiceTests).
add_executable(specus_c_public_transfer_tests tests/public_transfer_tests.c)
target_link_libraries(specus_c_public_transfer_tests PRIVATE specus_c_core)
target_compile_options(specus_c_public_transfer_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME public_transfer_tests COMMAND specus_c_public_transfer_tests)
set_tests_properties(public_transfer_tests PROPERTIES TIMEOUT 120)
add_test(NAME public_transfer_environment_guard_tests
    COMMAND specus_c_public_transfer_tests --check-environment-guard)

# The shared product metrics vector through the real request handling, the write-path hooks, and a
# real server process (client_online on a control login, the HTTP layer's body hand-over).
add_executable(specus_c_product_metrics_tests tests/product_metrics_tests.c tests/server_harness.c)
target_link_libraries(specus_c_product_metrics_tests PRIVATE specus_c_core)
target_compile_options(specus_c_product_metrics_tests PRIVATE -Wall -Wextra -Wpedantic)
target_compile_definitions(specus_c_product_metrics_tests PRIVATE
    ST_PRODUCT_METRICS_VECTOR_FILE="${CMAKE_CURRENT_SOURCE_DIR}/../../../protocol/test-vectors/product-metrics-v1.json")
add_test(NAME product_metrics_tests
    COMMAND specus_c_product_metrics_tests $<TARGET_FILE:specus-server-c>)
set_tests_properties(product_metrics_tests PROPERTIES TIMEOUT 180)

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

add_executable(specus_c_session_lifecycle_tests tests/session_lifecycle_tests.c tests/server_harness.c)
target_link_libraries(specus_c_session_lifecycle_tests PRIVATE specus_c_core)
target_compile_options(specus_c_session_lifecycle_tests PRIVATE -Wall -Wextra -Wpedantic)
target_compile_definitions(specus_c_session_lifecycle_tests PRIVATE
    ST_NAT_CONTROL_SIZE_VECTOR_FILE="${CMAKE_CURRENT_SOURCE_DIR}/../../../protocol/test-vectors/nat-control-size-v1.json")
add_test(NAME session_lifecycle_tests
    COMMAND specus_c_session_lifecycle_tests $<TARGET_FILE:specus-server-c>)
set_tests_properties(session_lifecycle_tests PROPERTIES TIMEOUT 120)

# Java SecurityRulesTests on a real server process: public transfer grants and callbacks, the public
# HTTP entry against foreign tokens and portal headers, the portal policy and the cloud diagram API.
add_executable(specus_c_security_rules_tests tests/security_rules_tests.c tests/server_harness.c)
target_link_libraries(specus_c_security_rules_tests PRIVATE specus_c_core)
target_compile_options(specus_c_security_rules_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME security_rules_tests
    COMMAND specus_c_security_rules_tests $<TARGET_FILE:specus-server-c>)
set_tests_properties(security_rules_tests PROPERTIES TIMEOUT 120)

# Java HttpWebSocketRoutingTests on a real server process: how /http/** splits WebSocket upgrades
# from plain requests, raw query characters, and the public route runtime asset.
add_executable(specus_c_server_harness_tests tests/server_harness_tests.c tests/server_harness.c)
target_link_libraries(specus_c_server_harness_tests PRIVATE specus_c_core)
target_compile_options(specus_c_server_harness_tests PRIVATE -Wall -Wextra -Wpedantic)
target_link_options(specus_c_server_harness_tests PRIVATE -Wl,--wrap=bind)
add_test(NAME server_harness_tests COMMAND specus_c_server_harness_tests $<TARGET_FILE:specus-server-c>)
set_tests_properties(server_harness_tests PROPERTIES TIMEOUT 60)

add_executable(specus_c_http_websocket_routing_tests tests/http_websocket_routing_tests.c tests/server_harness.c)
target_link_libraries(specus_c_http_websocket_routing_tests PRIVATE specus_c_core)
target_compile_options(specus_c_http_websocket_routing_tests PRIVATE -Wall -Wextra -Wpedantic)
target_compile_definitions(specus_c_http_websocket_routing_tests PRIVATE
    ST_ADMIN_WEB_PUBLIC_DIR="${CMAKE_CURRENT_SOURCE_DIR}/../../../apps/admin-web/public")
add_test(NAME http_websocket_routing_tests
    COMMAND specus_c_http_websocket_routing_tests $<TARGET_FILE:specus-server-c>)
set_tests_properties(http_websocket_routing_tests PROPERTIES TIMEOUT 120)

# Java ConnectionArchiveServiceTests on a real server process: the scheduled monthly archive.
add_executable(specus_c_connection_archive_tests tests/connection_archive_tests.c tests/server_harness.c)
target_link_libraries(specus_c_connection_archive_tests PRIVATE specus_c_core)
target_compile_options(specus_c_connection_archive_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME connection_archive_tests
    COMMAND specus_c_connection_archive_tests $<TARGET_FILE:specus-server-c>)
set_tests_properties(connection_archive_tests PROPERTIES TIMEOUT 120)

add_executable(specus_c_http_route_lifecycle_tests tests/http_route_lifecycle_tests.c tests/server_harness.c)
target_link_libraries(specus_c_http_route_lifecycle_tests PRIVATE specus_c_core)
target_compile_options(specus_c_http_route_lifecycle_tests PRIVATE -Wall -Wextra -Wpedantic)
target_compile_definitions(specus_c_http_route_lifecycle_tests PRIVATE
    ST_ROUTE_LIFECYCLE_VECTOR_FILE="${CMAKE_CURRENT_SOURCE_DIR}/../../../protocol/test-vectors/http-route-lifecycle-v1.json")
add_test(NAME http_route_lifecycle_tests
    COMMAND specus_c_http_route_lifecycle_tests $<TARGET_FILE:specus-server-c>)
set_tests_properties(http_route_lifecycle_tests PROPERTIES TIMEOUT 180)

# More than 64 TCP mappings and HTTP routes on one client, and the NAT_CONTROL message limit, on a
# real server process: login answer, NAT_CONTROL, runtime push, client detail and lists; and a
# configuration already past the limit (nat-control-size-v1.json existingOversize).
add_executable(specus_c_client_route_scale_tests tests/client_route_scale_tests.c tests/server_harness.c)
target_link_libraries(specus_c_client_route_scale_tests PRIVATE specus_c_core)
target_compile_options(specus_c_client_route_scale_tests PRIVATE -Wall -Wextra -Wpedantic)
target_compile_definitions(specus_c_client_route_scale_tests PRIVATE
    ST_NAT_CONTROL_SIZE_VECTOR_FILE="${CMAKE_CURRENT_SOURCE_DIR}/../../../protocol/test-vectors/nat-control-size-v1.json")
add_test(NAME client_route_scale_tests
    COMMAND specus_c_client_route_scale_tests $<TARGET_FILE:specus-server-c>)
set_tests_properties(client_route_scale_tests PROPERTIES TIMEOUT 180)

add_executable(specus_c_nat_stream_tests tests/nat_stream_tests.c tests/server_harness.c)
target_link_libraries(specus_c_nat_stream_tests PRIVATE specus_c_core)
target_compile_options(specus_c_nat_stream_tests PRIVATE -Wall -Wextra -Wpedantic)
target_compile_definitions(specus_c_nat_stream_tests PRIVATE
    ST_CONNECTIVITY_VECTOR_DIR="${CMAKE_CURRENT_SOURCE_DIR}/../../../protocol/test-vectors/")
add_test(NAME nat_stream_tests
    COMMAND specus_c_nat_stream_tests $<TARGET_FILE:specus-server-c>)
set_tests_properties(nat_stream_tests PROPERTIES TIMEOUT 420)

# Public TCP connections of the data connection as Java's NatServerHandler and Netty handle them.
# The checks read the server back through Linux's sock_diag, prlimit and /proc.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_executable(specus_c_nat_public_tcp_tests tests/nat_public_tcp_tests.c tests/server_harness.c)
    target_link_libraries(specus_c_nat_public_tcp_tests PRIVATE specus_c_core)
    target_compile_options(specus_c_nat_public_tcp_tests PRIVATE -Wall -Wextra -Wpedantic)
    add_test(NAME nat_public_tcp_tests
        COMMAND specus_c_nat_public_tcp_tests $<TARGET_FILE:specus-server-c>)
    set_tests_properties(nat_public_tcp_tests PROPERTIES TIMEOUT 300)
endif()

add_executable(specus_c_storage_tests tests/storage_tests.c)
target_link_libraries(specus_c_storage_tests PRIVATE specus_c_core)
target_compile_options(specus_c_storage_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME storage_tests COMMAND specus_c_storage_tests)

add_executable(specus_c_session_order_tests tests/session_order_tests.c)
target_link_libraries(specus_c_session_order_tests PRIVATE specus_c_core)
target_compile_options(specus_c_session_order_tests PRIVATE -Wall -Wextra -Wpedantic)
target_compile_definitions(specus_c_session_order_tests PRIVATE
    ST_SESSION_ORDER_VECTOR_FILE="${CMAKE_CURRENT_SOURCE_DIR}/../../../protocol/test-vectors/peer-egress-session-order-v1.json")
add_test(NAME session_order_tests COMMAND specus_c_session_order_tests)

add_executable(specus_c_session_scope_tests tests/session_order_tests.c)
target_link_libraries(specus_c_session_scope_tests PRIVATE specus_c_core)
target_compile_options(specus_c_session_scope_tests PRIVATE -Wall -Wextra -Wpedantic)
target_compile_definitions(specus_c_session_scope_tests PRIVATE
    ST_SESSION_ORDER_VECTOR_FILE="${CMAKE_CURRENT_SOURCE_DIR}/../../../protocol/test-vectors/peer-egress-session-scope-v1.json"
    ST_SESSION_ORDER_EXPECTED_CASES=8U ST_SESSION_SCOPE_NOCASE=1)
add_test(NAME session_scope_tests COMMAND specus_c_session_scope_tests)

add_executable(specus_c_stun_turn_tests tests/stun_turn_tests.c)
target_link_libraries(specus_c_stun_turn_tests PRIVATE specus_c_core)
target_compile_options(specus_c_stun_turn_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME stun_turn_tests COMMAND specus_c_stun_turn_tests)

# The meters Java registers with Micrometer and its actuator metrics endpoint: values, Java's
# Double.toString, the exposure settings, content negotiation and every answer of the two routes.
add_executable(specus_c_metrics_tests tests/metrics_tests.c)
target_link_libraries(specus_c_metrics_tests PRIVATE specus_c_core)
target_compile_options(specus_c_metrics_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME metrics_tests COMMAND specus_c_metrics_tests)

# The endpoint of a real server process, scraped after control-channel and TURN traffic and a
# Peer Mesh relay batch.
add_executable(specus_c_metrics_endpoint_tests tests/metrics_endpoint_tests.c tests/server_harness.c)
target_link_libraries(specus_c_metrics_endpoint_tests PRIVATE specus_c_core)
target_compile_options(specus_c_metrics_endpoint_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME metrics_endpoint_tests
    COMMAND specus_c_metrics_endpoint_tests $<TARGET_FILE:specus-server-c>)
set_tests_properties(metrics_endpoint_tests PROPERTIES TIMEOUT 120)

add_executable(specus_c_stun_turn_scale_tests tests/stun_turn_scale_tests.c)
target_link_libraries(specus_c_stun_turn_scale_tests PRIVATE specus_c_core)
target_compile_options(specus_c_stun_turn_scale_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME stun_turn_scale_tests COMMAND specus_c_stun_turn_scale_tests)

add_executable(specus_c_workbench_tests tests/workbench_tests.c tests/server_harness.c)
target_link_libraries(specus_c_workbench_tests PRIVATE specus_c_core)
target_compile_options(specus_c_workbench_tests PRIVATE -Wall -Wextra -Wpedantic)
target_compile_definitions(specus_c_workbench_tests PRIVATE
    ST_WORKBENCH_VECTOR_FILE="${CMAKE_CURRENT_SOURCE_DIR}/../../../protocol/test-vectors/service-workbench-v1.json")
add_test(NAME workbench_tests COMMAND specus_c_workbench_tests)

add_executable(specus_c_management_accounts_tests tests/management_accounts_tests.c)
target_link_libraries(specus_c_management_accounts_tests PRIVATE specus_c_core)
target_compile_options(specus_c_management_accounts_tests PRIVATE -Wall -Wextra -Wpedantic)
target_compile_definitions(specus_c_management_accounts_tests PRIVATE
    ST_MANAGEMENT_ACCOUNTS_VECTOR_FILE="${CMAKE_CURRENT_SOURCE_DIR}/../../../protocol/test-vectors/management-accounts-v1.json")
add_test(NAME management_accounts_tests COMMAND specus_c_management_accounts_tests)

add_executable(specus_c_tls_transport_tests tests/tls_transport_tests.c)
target_link_libraries(specus_c_tls_transport_tests PRIVATE specus_c_core)
target_compile_options(specus_c_tls_transport_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME tls_transport_tests COMMAND specus_c_tls_transport_tests)
# The production TLS rule on the real binary: refusal of a public plaintext control listener, PEM
# file TLS verified with openssl s_client.
add_test(NAME tls_deployment_e2e
    COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/tls_deployment_e2e.sh
                 $<TARGET_FILE:specus-server-c>)
set_tests_properties(tls_deployment_e2e PROPERTIES TIMEOUT 90)

# Keep the deterministic wall-clock regression separate from the real HTTP package suite.
add_executable(specus_c_client_package_clock_tests tests/client_package_clock_tests.c)
target_link_libraries(specus_c_client_package_clock_tests PRIVATE specus_c_core)
target_compile_options(specus_c_client_package_clock_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME client_package_clock_tests COMMAND specus_c_client_package_clock_tests)

# Process-local adverse clock view; the normal NAT test and its 10s lower bound are unchanged.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_library(specus_c_connectivity_clock_offset SHARED tests/connectivity_clock_offset.c)
    target_compile_options(specus_c_connectivity_clock_offset PRIVATE -Wall -Wextra -Wpedantic)
    add_test(NAME nat_connectivity_clock_adjustment
        COMMAND ${CMAKE_COMMAND} -E env
            "LD_PRELOAD=$<TARGET_FILE:specus_c_connectivity_clock_offset>"
            "SPECUS_NAT_STREAM_ONLY=connectivity NAT complete"
            $<TARGET_FILE:specus_c_nat_stream_tests> $<TARGET_FILE:specus-server-c>)
    set_tests_properties(nat_connectivity_clock_adjustment PROPERTIES TIMEOUT 60)
    # The SPECUS_HTTP_TIMEOUT_MS waits of a route request, under the same wall clock 3 s behind.
    add_test(NAME nat_http_timeout_clock_adjustment
        COMMAND ${CMAKE_COMMAND} -E env
            "LD_PRELOAD=$<TARGET_FILE:specus_c_connectivity_clock_offset>"
            "SPECUS_NAT_STREAM_ONLY=SPECUS_HTTP_"
            $<TARGET_FILE:specus_c_nat_stream_tests> $<TARGET_FILE:specus-server-c>)
    set_tests_properties(nat_http_timeout_clock_adjustment PROPERTIES TIMEOUT 60)
endif()

# Reference tests compile private main.c code without adding switches to the shipped server.
add_executable(specus_c_control_write_reference_tests tests/control_write_reference_tests.c)
target_link_libraries(specus_c_control_write_reference_tests PRIVATE specus_c_core)
target_compile_options(specus_c_control_write_reference_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME control_write_reference_tests COMMAND specus_c_control_write_reference_tests)
set_tests_properties(control_write_reference_tests PROPERTIES TIMEOUT 30)

# A stopped TCP stream keeps its descriptor until neither worker can still recv/send on it.
add_executable(specus_c_stream_fd_lifetime_tests tests/stream_fd_lifetime_tests.c)
target_link_libraries(specus_c_stream_fd_lifetime_tests PRIVATE specus_c_core)
target_compile_options(specus_c_stream_fd_lifetime_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME stream_fd_lifetime_tests COMMAND specus_c_stream_fd_lifetime_tests)
set_tests_properties(stream_fd_lifetime_tests PROPERTIES TIMEOUT 60)

# Only this object aliases the three observation points. The helper forwards real I/O, registry
# and metrics calls; the ordinary specus-server-c target above never links this helper.
add_library(specus_c_session_reference_main OBJECT src/main.c)
target_link_libraries(specus_c_session_reference_main PRIVATE specus_c_core)
target_compile_options(specus_c_session_reference_main PRIVATE -Wall -Wextra -Wpedantic
    -include "${CMAKE_CURRENT_SOURCE_DIR}/tests/session_reference_recv.h")
target_compile_definitions(specus_c_session_reference_main PRIVATE
    st_peer_mesh_push_on_logout=st_fixture_peer_logout
    st_product_metrics_milestone=st_fixture_milestone)
add_executable(specus_c_session_reference_server
    $<TARGET_OBJECTS:specus_c_session_reference_main> tests/session_reference_observer.c)
target_link_libraries(specus_c_session_reference_server PRIVATE specus_c_core)
target_compile_options(specus_c_session_reference_server PRIVATE -Wall -Wextra -Wpedantic)
add_executable(specus_c_session_reference_tests tests/session_reference_tests.c tests/server_harness.c)
target_link_libraries(specus_c_session_reference_tests PRIVATE specus_c_core)
target_compile_options(specus_c_session_reference_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME session_reference_tests
    COMMAND specus_c_session_reference_tests $<TARGET_FILE:specus_c_session_reference_server>)
set_tests_properties(session_reference_tests PROPERTIES TIMEOUT 120)

# Java HttpSpecusControllerStreamResetTests: pure formatting plus real public HTTP/RST,
# traffic-detail persistence and continued use of the same client control/data session.
add_executable(specus_c_http_log_reason_reference_tests tests/http_log_reason_reference_tests.c)
target_link_libraries(specus_c_http_log_reason_reference_tests PRIVATE specus_c_core)
target_compile_options(specus_c_http_log_reason_reference_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME http_log_reason_reference_tests COMMAND specus_c_http_log_reason_reference_tests)
set_tests_properties(http_log_reason_reference_tests PROPERTIES TIMEOUT 30)

add_executable(specus_c_http_reset_reason_reference_tests
    tests/http_reset_reason_reference_tests.c tests/server_harness.c)
target_link_libraries(specus_c_http_reset_reason_reference_tests PRIVATE specus_c_core)
target_compile_options(specus_c_http_reset_reason_reference_tests PRIVATE -Wall -Wextra -Wpedantic)
target_compile_definitions(specus_c_http_reset_reason_reference_tests PRIVATE
    ST_CONNECTIVITY_VECTOR_DIR="${CMAKE_CURRENT_SOURCE_DIR}/../../../protocol/test-vectors/")
add_test(NAME http_reset_reason_reference_tests
    COMMAND specus_c_http_reset_reason_reference_tests $<TARGET_FILE:specus-server-c>)
set_tests_properties(http_reset_reason_reference_tests PROPERTIES TIMEOUT 60)

# Traffic usage of a real server process: what is counted, in which direction, and when it is written.
add_executable(specus_c_traffic_usage_tests tests/traffic_usage_tests.c tests/server_harness.c)
target_link_libraries(specus_c_traffic_usage_tests PRIVATE specus_c_core)
target_compile_options(specus_c_traffic_usage_tests PRIVATE -Wall -Wextra -Wpedantic)
target_compile_definitions(specus_c_traffic_usage_tests PRIVATE
    ST_CONNECTIVITY_VECTOR_DIR="${CMAKE_CURRENT_SOURCE_DIR}/../../../protocol/test-vectors/")
add_test(NAME traffic_usage_tests COMMAND specus_c_traffic_usage_tests $<TARGET_FILE:specus-server-c>)
set_tests_properties(traffic_usage_tests PROPERTIES TIMEOUT 120)

# The public listener's Tomcat connector limits and the answers of failed route requests, on a real
# server process (connection timeout, max connections, 100-continue, 504/502 and RST 8).
add_executable(specus_c_http_connector_tests tests/http_connector_tests.c tests/server_harness.c)
target_link_libraries(specus_c_http_connector_tests PRIVATE specus_c_core)
target_compile_options(specus_c_http_connector_tests PRIVATE -Wall -Wextra -Wpedantic)
target_compile_definitions(specus_c_http_connector_tests PRIVATE
    ST_CONNECTIVITY_VECTOR_DIR="${CMAKE_CURRENT_SOURCE_DIR}/../../../protocol/test-vectors/")
add_test(NAME http_connector_tests COMMAND specus_c_http_connector_tests $<TARGET_FILE:specus-server-c>)
set_tests_properties(http_connector_tests PROPERTIES TIMEOUT 180)

# TCP_INFO observes a real kernel reset before releasing the held login. These observers
# belong only to this test server; specus-server-c does not link or enable them.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_executable(specus_c_nat_push_reference_server tests/nat_push_reference_server.c)
    target_link_libraries(specus_c_nat_push_reference_server PRIVATE specus_c_core)
    target_compile_options(specus_c_nat_push_reference_server PRIVATE -Wall -Wextra -Wpedantic)
    add_executable(specus_c_nat_push_reference_tests
        tests/nat_push_reference_tests.c tests/server_harness.c)
    target_link_libraries(specus_c_nat_push_reference_tests PRIVATE specus_c_core)
    target_compile_options(specus_c_nat_push_reference_tests PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_definitions(specus_c_nat_push_reference_tests PRIVATE
        ST_NAT_CONTROL_SIZE_VECTOR_FILE="${CMAKE_CURRENT_SOURCE_DIR}/../../../protocol/test-vectors/nat-control-size-v1.json")
    add_test(NAME nat_push_reference_tests
        COMMAND specus_c_nat_push_reference_tests $<TARGET_FILE:specus_c_nat_push_reference_server>)
    set_tests_properties(nat_push_reference_tests PROPERTIES TIMEOUT 90)
endif()

# Exact shared sizing and management vectors use the real JSON builder and normal server.
add_executable(specus_c_nat_sizing_reference_tests
    tests/nat_sizing_reference_tests.c tests/server_harness.c)
target_link_libraries(specus_c_nat_sizing_reference_tests PRIVATE specus_c_core)
target_compile_options(specus_c_nat_sizing_reference_tests PRIVATE -Wall -Wextra -Wpedantic)
target_compile_definitions(specus_c_nat_sizing_reference_tests PRIVATE
    ST_NAT_CONTROL_SIZE_VECTOR_FILE="${CMAKE_CURRENT_SOURCE_DIR}/../../../protocol/test-vectors/nat-control-size-v1.json")
add_test(NAME nat_sizing_reference_tests
    COMMAND specus_c_nat_sizing_reference_tests $<TARGET_FILE:specus-server-c>)
set_tests_properties(nat_sizing_reference_tests PROPERTIES TIMEOUT 90)

add_executable(specus_c_sqlite_reference_tests tests/sqlite_reference_tests.c)
target_link_libraries(specus_c_sqlite_reference_tests PRIVATE specus_c_core)
target_compile_options(specus_c_sqlite_reference_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME sqlite_reference_tests COMMAND specus_c_sqlite_reference_tests)
set_tests_properties(sqlite_reference_tests PROPERTIES TIMEOUT 60)

foreach(test_name IN ITEMS websocket_ticket_request websocket_ticket_quota websocket_ticket_account)
    add_executable(specus_c_${test_name}_tests tests/${test_name}_tests.c)
    target_link_libraries(specus_c_${test_name}_tests PRIVATE specus_c_core pthread)
    target_compile_options(specus_c_${test_name}_tests PRIVATE -Wall -Wextra -Wpedantic)
    target_link_options(specus_c_${test_name}_tests PRIVATE -Wl,--wrap=clock_gettime)
    add_test(NAME ${test_name}_tests COMMAND specus_c_${test_name}_tests)
    set_tests_properties(${test_name}_tests PROPERTIES TIMEOUT 120)
endforeach()
# About 30 s alone, but its ~2,100 SQLite commits each wait for an fsync, which a busy disk
# stretches past 100 s.
set_tests_properties(websocket_ticket_quota_tests PROPERTIES TIMEOUT 240)

add_executable(specus_c_registration_expiry_tests tests/registration_expiry_tests.c)
target_link_libraries(specus_c_registration_expiry_tests PRIVATE specus_c_core)
target_compile_options(specus_c_registration_expiry_tests PRIVATE -Wall -Wextra -Wpedantic)
target_link_options(specus_c_registration_expiry_tests PRIVATE -Wl,--wrap=time -Wl,--wrap=clock_gettime)
add_test(NAME registration_expiry_tests COMMAND specus_c_registration_expiry_tests)
set_tests_properties(registration_expiry_tests PROPERTIES TIMEOUT 30)

add_test(NAME websocket_ticket_restart_tests
    COMMAND python3 ${CMAKE_CURRENT_SOURCE_DIR}/tests/websocket_ticket_restart_tests.py $<TARGET_FILE:specus-server-c>)
set_tests_properties(websocket_ticket_restart_tests PROPERTIES TIMEOUT 60 ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")

foreach(test_name IN ITEMS instant instant_migration connection_time_reference auth_expiry_reference websocket_ticket_storage_reference)
    add_executable(specus_c_${test_name}_tests tests/${test_name}_tests.c)
    target_link_libraries(specus_c_${test_name}_tests PRIVATE specus_c_core)
    target_compile_options(specus_c_${test_name}_tests PRIVATE -Wall -Wextra -Wpedantic)
    add_test(NAME ${test_name}_tests COMMAND specus_c_${test_name}_tests)
    set_tests_properties(${test_name}_tests PROPERTIES TIMEOUT 60)
endforeach()

add_executable(specus_c_peer_session_expiry_tests tests/peer_session_expiry_tests.c)
target_link_libraries(specus_c_peer_session_expiry_tests PRIVATE specus_c_core)
target_compile_options(specus_c_peer_session_expiry_tests PRIVATE -Wall -Wextra -Wpedantic)
target_link_options(specus_c_peer_session_expiry_tests PRIVATE -Wl,--wrap=clock_gettime)
add_test(NAME peer_session_expiry_tests COMMAND specus_c_peer_session_expiry_tests)
set_tests_properties(peer_session_expiry_tests PROPERTIES TIMEOUT 60)

add_executable(specus_c_pairing_expiry_tests tests/pairing_expiry_tests.c)
target_link_libraries(specus_c_pairing_expiry_tests PRIVATE specus_c_core)
target_compile_options(specus_c_pairing_expiry_tests PRIVATE -Wall -Wextra -Wpedantic)
target_link_options(specus_c_pairing_expiry_tests PRIVATE -Wl,--wrap=time -Wl,--wrap=clock_gettime)
add_test(NAME pairing_expiry_tests COMMAND specus_c_pairing_expiry_tests)
set_tests_properties(pairing_expiry_tests PROPERTIES TIMEOUT 60)

add_executable(specus_c_transfer_expiry_tests tests/transfer_expiry_tests.c)
target_link_libraries(specus_c_transfer_expiry_tests PRIVATE specus_c_core)
target_compile_options(specus_c_transfer_expiry_tests PRIVATE -Wall -Wextra -Wpedantic)
target_link_options(specus_c_transfer_expiry_tests PRIVATE -Wl,--wrap=time -Wl,--wrap=clock_gettime)
add_test(NAME transfer_expiry_tests COMMAND specus_c_transfer_expiry_tests)
set_tests_properties(transfer_expiry_tests PROPERTIES TIMEOUT 90)

add_executable(specus_c_media_expiry_tests tests/media_expiry_tests.c)
target_link_libraries(specus_c_media_expiry_tests PRIVATE specus_c_core)
target_compile_options(specus_c_media_expiry_tests PRIVATE -Wall -Wextra -Wpedantic)
target_link_options(specus_c_media_expiry_tests PRIVATE -Wl,--wrap=time -Wl,--wrap=clock_gettime)
add_test(NAME media_expiry_tests COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/scripts/media_capture_test.sh
    $<TARGET_FILE:specus_c_media_expiry_tests> expiry)
set_tests_properties(media_expiry_tests PROPERTIES TIMEOUT 90)
