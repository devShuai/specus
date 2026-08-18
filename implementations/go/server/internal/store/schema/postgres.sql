CREATE TABLE IF NOT EXISTS specus_client_account (
  id BIGINT PRIMARY KEY,
  tenant_id VARCHAR(80) NOT NULL DEFAULT 'default',
  owner_username VARCHAR(80),
  client_name VARCHAR(120) NOT NULL UNIQUE,
  password_hash VARCHAR(64) NOT NULL,
  enabled SMALLINT NOT NULL,
  connection_rate_limit_per_minute INTEGER NOT NULL,
  created_at VARCHAR(40) NOT NULL,
  updated_at VARCHAR(40) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_specus_client_tenant ON specus_client_account (tenant_id);
CREATE INDEX IF NOT EXISTS idx_specus_client_owner ON specus_client_account (tenant_id, owner_username);

CREATE TABLE IF NOT EXISTS specus_client_credential (
  id BIGINT PRIMARY KEY,
  tenant_id VARCHAR(80) NOT NULL,
  owner_username VARCHAR(80),
  api_key VARCHAR(120) NOT NULL UNIQUE,
  secret_hash VARCHAR(64) NOT NULL,
  enabled SMALLINT NOT NULL,
  max_online_instances INTEGER NOT NULL,
  created_at VARCHAR(40) NOT NULL,
  updated_at VARCHAR(40) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_client_credential_tenant ON specus_client_credential (tenant_id);
CREATE INDEX IF NOT EXISTS idx_client_credential_owner ON specus_client_credential (tenant_id, owner_username);

CREATE TABLE IF NOT EXISTS specus_client_auth_nonce (
  id VARCHAR(64) PRIMARY KEY,
  api_key_hash VARCHAR(64) NOT NULL,
  expires_at VARCHAR(40) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_client_auth_nonce_expires ON specus_client_auth_nonce (expires_at);

CREATE TABLE IF NOT EXISTS specus_websocket_ticket (
  token_hash VARCHAR(64) PRIMARY KEY,
  scope VARCHAR(40) NOT NULL,
  attributes_json TEXT NOT NULL,
  username VARCHAR(80),
  tenant_id VARCHAR(80),
  is_admin SMALLINT NOT NULL DEFAULT 0,
  room_id VARCHAR(120),
  room_key VARCHAR(80),
  room_role VARCHAR(16),
  peer_id VARCHAR(120),
  display_name VARCHAR(120),
  shared_room SMALLINT NOT NULL DEFAULT 0,
  remote_address_hash VARCHAR(64) NOT NULL,
  created_at VARCHAR(40) NOT NULL,
  expires_at VARCHAR(40) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_websocket_ticket_expiry ON specus_websocket_ticket (expires_at);

CREATE TABLE IF NOT EXISTS specus_client_identity (
  id BIGINT PRIMARY KEY,
  tenant_id VARCHAR(80) NOT NULL,
  credential_id BIGINT NOT NULL,
  client_id BIGINT NOT NULL,
  client_name VARCHAR(120) NOT NULL,
  machine_fingerprint VARCHAR(160) NOT NULL,
  os_user VARCHAR(120) NOT NULL,
  hostname VARCHAR(160),
  first_seen_at VARCHAR(40) NOT NULL,
  last_seen_at VARCHAR(40) NOT NULL,
  UNIQUE (credential_id, machine_fingerprint, os_user)
);

CREATE INDEX IF NOT EXISTS idx_client_identity_tenant ON specus_client_identity (tenant_id);
CREATE INDEX IF NOT EXISTS idx_client_identity_client ON specus_client_identity (client_id);

CREATE TABLE IF NOT EXISTS specus_client_session (
  id BIGINT PRIMARY KEY,
  tenant_id VARCHAR(80) NOT NULL,
  credential_id BIGINT NOT NULL,
  identity_id BIGINT NOT NULL,
  client_id BIGINT NOT NULL,
  client_name VARCHAR(120) NOT NULL,
  token_hash VARCHAR(64) NOT NULL UNIQUE,
  status VARCHAR(40) NOT NULL,
  machine_fingerprint VARCHAR(160) NOT NULL,
  os_user VARCHAR(120) NOT NULL,
  hostname VARCHAR(160),
  os_name VARCHAR(120),
  os_version VARCHAR(80),
  os_arch VARCHAR(60),
  client_version VARCHAR(80),
  java_version VARCHAR(80),
  local_addresses VARCHAR(2000),
  message_send_capable BOOLEAN NOT NULL DEFAULT FALSE,
  message_receive_capable BOOLEAN NOT NULL DEFAULT FALSE,
  message_attachments_capable BOOLEAN NOT NULL DEFAULT FALSE,
  message_media_preview_capable BOOLEAN NOT NULL DEFAULT FALSE,
  message_max_attachment_bytes BIGINT NOT NULL DEFAULT 0,
  http_login_at VARCHAR(40) NOT NULL,
  netty_connected_at VARCHAR(40),
  disconnected_at VARCHAR(40),
  expires_at VARCHAR(40) NOT NULL,
  channel_id VARCHAR(160),
  remote_address VARCHAR(255)
);

CREATE INDEX IF NOT EXISTS idx_client_session_token ON specus_client_session (token_hash);
CREATE INDEX IF NOT EXISTS idx_client_session_credential_status ON specus_client_session (credential_id, status);
CREATE INDEX IF NOT EXISTS idx_client_session_machine_status ON specus_client_session (credential_id, machine_fingerprint, os_user, status);
CREATE INDEX IF NOT EXISTS idx_client_session_client_status ON specus_client_session (client_id, status);

CREATE TABLE IF NOT EXISTS specus_management_user (
  username VARCHAR(80) PRIMARY KEY,
  tenant_id VARCHAR(80) NOT NULL,
  password_hash VARCHAR(64) NOT NULL,
  oidc_issuer VARCHAR(255),
  oidc_subject VARCHAR(255),
  oidc_identity_key VARCHAR(64),
  role VARCHAR(20) NOT NULL,
  enabled SMALLINT NOT NULL,
  created_at VARCHAR(40) NOT NULL,
  updated_at VARCHAR(40) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_management_user_tenant ON specus_management_user (tenant_id);
CREATE INDEX IF NOT EXISTS idx_management_user_role ON specus_management_user (role);

CREATE TABLE IF NOT EXISTS specus_management_user_email (
  username VARCHAR(80) PRIMARY KEY,
  email VARCHAR(254) NOT NULL UNIQUE,
  verified_at VARCHAR(40) NOT NULL,
  created_at VARCHAR(40) NOT NULL,
  updated_at VARCHAR(40) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_management_user_email_verified ON specus_management_user_email (verified_at);

CREATE TABLE IF NOT EXISTS specus_management_registration_challenge (
  registration_id VARCHAR(64) PRIMARY KEY,
  username VARCHAR(80) NOT NULL,
  email VARCHAR(254) NOT NULL,
  password_hash VARCHAR(64) NOT NULL,
  code_hash VARCHAR(64) NOT NULL,
  attempts_remaining INTEGER NOT NULL,
  expires_at VARCHAR(40) NOT NULL,
  resend_available_at VARCHAR(40) NOT NULL,
  created_at VARCHAR(40) NOT NULL,
  updated_at VARCHAR(40) NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_registration_challenge_username ON specus_management_registration_challenge (LOWER(username));
CREATE UNIQUE INDEX IF NOT EXISTS uq_registration_challenge_email ON specus_management_registration_challenge (LOWER(email));

CREATE INDEX IF NOT EXISTS idx_registration_challenge_username ON specus_management_registration_challenge (username);
CREATE INDEX IF NOT EXISTS idx_registration_challenge_email ON specus_management_registration_challenge (email);
CREATE INDEX IF NOT EXISTS idx_registration_challenge_expiry ON specus_management_registration_challenge (expires_at);

CREATE TABLE IF NOT EXISTS client_download_link (
  id BIGINT PRIMARY KEY,
  implementation VARCHAR(32) NOT NULL,
  platform VARCHAR(32) NOT NULL,
  arch VARCHAR(32) NOT NULL,
  version VARCHAR(32) NOT NULL,
  display_name VARCHAR(120) NOT NULL,
  download_url VARCHAR(1024) NOT NULL,
  description VARCHAR(512),
  sha256 VARCHAR(64) NOT NULL DEFAULT '',
  file_size BIGINT NOT NULL DEFAULT 0,
  is_latest SMALLINT NOT NULL DEFAULT 0,
  latest_slot VARCHAR(160),
  changelog_url VARCHAR(1024),
  min_supported_version VARCHAR(32),
  display_order INTEGER NOT NULL DEFAULT 0,
  enabled SMALLINT NOT NULL DEFAULT 1,
  created_at VARCHAR(40) NOT NULL,
  updated_at VARCHAR(40) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_client_download_impl ON client_download_link (implementation);
CREATE INDEX IF NOT EXISTS idx_client_download_order ON client_download_link (display_order);

CREATE TABLE IF NOT EXISTS transfer_attachment (
  id BIGINT PRIMARY KEY,
  tenant_id VARCHAR(80),
  scope VARCHAR(40) NOT NULL,
  room_id VARCHAR(120),
  room_token_hash VARCHAR(64),
  public_transfer_room_id BIGINT,
  owner_username VARCHAR(80),
  target_client_id BIGINT,
  object_key VARCHAR(512) NOT NULL UNIQUE,
  file_name VARCHAR(255) NOT NULL,
  mime_type VARCHAR(120) NOT NULL,
  size_bytes BIGINT NOT NULL,
  sha256 VARCHAR(64),
  status VARCHAR(24) NOT NULL,
  created_at VARCHAR(40) NOT NULL,
  updated_at VARCHAR(40) NOT NULL,
  upload_expires_at VARCHAR(40) NOT NULL,
  expires_at VARCHAR(40) NOT NULL,
  uploaded_at VARCHAR(40)
);

CREATE INDEX IF NOT EXISTS idx_transfer_attachment_tenant ON transfer_attachment (tenant_id, scope, id);
CREATE INDEX IF NOT EXISTS idx_transfer_attachment_room ON transfer_attachment (scope, room_id, id);
CREATE INDEX IF NOT EXISTS idx_transfer_attachment_owner_status ON transfer_attachment (tenant_id, owner_username, status, expires_at);
CREATE INDEX IF NOT EXISTS idx_transfer_attachment_expires ON transfer_attachment (expires_at, status);

CREATE TABLE IF NOT EXISTS transfer_attachment_download_usage (
  id BIGINT PRIMARY KEY,
  tenant_id VARCHAR(80) NOT NULL,
  username VARCHAR(80) NOT NULL,
  attachment_id BIGINT NOT NULL,
  size_bytes BIGINT NOT NULL,
  usage_month VARCHAR(7) NOT NULL,
  created_at VARCHAR(40) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_attachment_download_usage_account_month
  ON transfer_attachment_download_usage (tenant_id, username, usage_month);
CREATE INDEX IF NOT EXISTS idx_attachment_download_usage_attachment
  ON transfer_attachment_download_usage (attachment_id, created_at);

CREATE TABLE IF NOT EXISTS transfer_attachment_download_grant (
  id BIGINT PRIMARY KEY,
  token_hash VARCHAR(64) NOT NULL UNIQUE,
  tenant_id VARCHAR(80) NOT NULL,
  username VARCHAR(120) NOT NULL,
  attachment_id BIGINT NOT NULL,
  created_at VARCHAR(64) NOT NULL,
  expires_at VARCHAR(64) NOT NULL,
  consumed_at VARCHAR(64)
);

CREATE INDEX IF NOT EXISTS idx_attachment_download_grant_attachment
  ON transfer_attachment_download_grant (attachment_id, created_at);
CREATE INDEX IF NOT EXISTS idx_attachment_download_grant_expiry
  ON transfer_attachment_download_grant (expires_at, consumed_at);

CREATE TABLE IF NOT EXISTS specus_connection_record (
  id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
  tenant_id VARCHAR(80),
  client_id BIGINT,
  client_name VARCHAR(120) NOT NULL,
  channel_id VARCHAR(160),
  remote_address VARCHAR(255),
  connected_at VARCHAR(40) NOT NULL,
  disconnected_at VARCHAR(40),
  success SMALLINT NOT NULL,
  failure_reason VARCHAR(255),
  disconnect_reason VARCHAR(40)
);

CREATE INDEX IF NOT EXISTS idx_specus_connection_tenant ON specus_connection_record (tenant_id);
CREATE INDEX IF NOT EXISTS idx_specus_connection_client_time ON specus_connection_record (client_id, connected_at);
CREATE INDEX IF NOT EXISTS idx_specus_connection_connected_at ON specus_connection_record (connected_at);

CREATE TABLE IF NOT EXISTS specus_mapping (
  id BIGINT PRIMARY KEY,
  tenant_id VARCHAR(80) NOT NULL,
  client_id BIGINT NOT NULL,
  client_name VARCHAR(120) NOT NULL,
  listen_port INTEGER NOT NULL UNIQUE,
  target_address VARCHAR(255) NOT NULL,
  target_port INTEGER NOT NULL,
  enabled SMALLINT NOT NULL,
  detail_capture_enabled SMALLINT NOT NULL DEFAULT 0,
  created_at VARCHAR(40) NOT NULL,
  updated_at VARCHAR(40) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_specus_mapping_client_id ON specus_mapping (client_id);

CREATE TABLE IF NOT EXISTS http_route_mapping (
  id BIGINT PRIMARY KEY,
  tenant_id VARCHAR(80) NOT NULL,
  client_id BIGINT NOT NULL,
  client_name VARCHAR(120) NOT NULL,
  route VARCHAR(60) NOT NULL,
  target_base_url VARCHAR(512) NOT NULL,
  enabled SMALLINT NOT NULL,
  detail_capture_enabled SMALLINT NOT NULL DEFAULT 0,
  media_capture_enabled SMALLINT NOT NULL DEFAULT 0,
  path_rewrite_enabled SMALLINT NOT NULL DEFAULT 0,
  auth_enabled SMALLINT NOT NULL DEFAULT 0,
  auth_username VARCHAR(120) NOT NULL DEFAULT '',
  auth_password_hash VARCHAR(64) NOT NULL DEFAULT '',
  created_at VARCHAR(40) NOT NULL,
  updated_at VARCHAR(40) NOT NULL,
  UNIQUE (client_id, route)
);

CREATE INDEX IF NOT EXISTS idx_http_route_client_id ON http_route_mapping (client_id);

CREATE TABLE IF NOT EXISTS specus_http_media_capture (
  id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
  tenant_id VARCHAR(80) NOT NULL,
  client_id BIGINT NOT NULL,
  client_name VARCHAR(120) NOT NULL,
  route VARCHAR(128) NOT NULL,
  resource_id BIGINT,
  source_url VARCHAR(3072) NOT NULL,
  resource_key VARCHAR(64) NOT NULL,
  deduplication_key VARCHAR(64) UNIQUE,
  method VARCHAR(16) NOT NULL,
  status_code INTEGER NOT NULL,
  content_type VARCHAR(255),
  content_encoding VARCHAR(128),
  media_kind VARCHAR(32) NOT NULL,
  entity_tag VARCHAR(512),
  last_modified VARCHAR(128),
  content_range_start BIGINT,
  content_range_end BIGINT,
  total_bytes BIGINT,
  captured_bytes BIGINT NOT NULL,
  segment_sequence BIGINT,
  initialization_segment BOOLEAN NOT NULL DEFAULT FALSE,
  live_stream BOOLEAN NOT NULL DEFAULT FALSE,
  object_key VARCHAR(1024) NOT NULL,
  upload_id VARCHAR(1024),
  object_etag VARCHAR(512),
  state VARCHAR(24) NOT NULL,
  failure_reason VARCHAR(2048),
  response_headers TEXT,
  captured_at VARCHAR(40) NOT NULL,
  completed_at VARCHAR(40),
  expires_at VARCHAR(40) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_http_media_tenant_id ON specus_http_media_capture (tenant_id, id);
CREATE INDEX IF NOT EXISTS idx_http_media_tenant_client_id ON specus_http_media_capture (tenant_id, client_id, id);
CREATE INDEX IF NOT EXISTS idx_http_media_resource ON specus_http_media_capture (tenant_id, resource_key, id);
CREATE INDEX IF NOT EXISTS idx_http_media_source ON specus_http_media_capture (tenant_id, client_id, route, id);
CREATE INDEX IF NOT EXISTS idx_http_media_expiry ON specus_http_media_capture (state, expires_at);

CREATE TABLE IF NOT EXISTS specus_http_media_reference (
  id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
  tenant_id VARCHAR(80) NOT NULL,
  manifest_capture_id BIGINT NOT NULL,
  relation_type VARCHAR(24) NOT NULL,
  sequence_index BIGINT,
  original_uri VARCHAR(2048) NOT NULL,
  resolved_source_url VARCHAR(3072) NOT NULL,
  created_at VARCHAR(40) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_http_media_ref_manifest ON specus_http_media_reference (tenant_id, manifest_capture_id, sequence_index);
CREATE INDEX IF NOT EXISTS idx_http_media_ref_source ON specus_http_media_reference (tenant_id, manifest_capture_id);

CREATE TABLE IF NOT EXISTS specus_traffic_usage (
  id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
  tenant_id VARCHAR(80),
  client_id BIGINT NOT NULL,
  client_name VARCHAR(120) NOT NULL,
  usage_date VARCHAR(10) NOT NULL,
  upload_bytes BIGINT NOT NULL,
  download_bytes BIGINT NOT NULL,
  updated_at VARCHAR(40) NOT NULL,
  UNIQUE (client_id, usage_date)
);

CREATE INDEX IF NOT EXISTS idx_specus_traffic_tenant ON specus_traffic_usage (tenant_id);
CREATE INDEX IF NOT EXISTS idx_traffic_client_id ON specus_traffic_usage (client_id);

CREATE TABLE IF NOT EXISTS specus_resource_traffic_usage (
  id BIGSERIAL PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  client_id BIGINT NOT NULL,
  client_name TEXT NOT NULL,
  resource_type TEXT NOT NULL,
  resource_key TEXT NOT NULL,
  resource_id BIGINT,
  resource_name TEXT NOT NULL,
  usage_date TEXT NOT NULL,
  upload_bytes BIGINT NOT NULL,
  download_bytes BIGINT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (tenant_id, client_id, resource_type, resource_key, usage_date)
);

CREATE INDEX IF NOT EXISTS idx_resource_traffic_tenant ON specus_resource_traffic_usage (tenant_id);
CREATE INDEX IF NOT EXISTS idx_resource_traffic_client ON specus_resource_traffic_usage (client_id);
CREATE INDEX IF NOT EXISTS idx_resource_traffic_type ON specus_resource_traffic_usage (resource_type);
CREATE INDEX IF NOT EXISTS idx_resource_traffic_date ON specus_resource_traffic_usage (usage_date);

CREATE TABLE IF NOT EXISTS specus_http_traffic_exchange (
  id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
  tenant_id VARCHAR(80) NOT NULL,
  client_id BIGINT NOT NULL,
  client_name VARCHAR(120) NOT NULL,
  route VARCHAR(128) NOT NULL,
  resource_id BIGINT,
  resource_name VARCHAR(255),
  method VARCHAR(16),
  relative_path VARCHAR(1024),
  raw_query VARCHAR(2048),
  status_code INTEGER NOT NULL,
  success SMALLINT NOT NULL,
  error VARCHAR(2048),
  remote_address VARCHAR(255),
  request_bytes BIGINT NOT NULL,
  response_bytes BIGINT NOT NULL,
  elapsed_ms BIGINT NOT NULL,
  request_content_type VARCHAR(255),
  response_content_type VARCHAR(255),
  response_body_type VARCHAR(32),
  request_headers VARCHAR(8192),
  response_headers VARCHAR(8192),
  request_preview_hex VARCHAR(4096),
  request_preview_text TEXT,
  response_preview_hex VARCHAR(4096),
  response_preview_text TEXT,
  request_truncated SMALLINT NOT NULL,
  response_truncated SMALLINT NOT NULL,
  captured_at VARCHAR(40) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_http_traffic_tenant ON specus_http_traffic_exchange (tenant_id);
CREATE INDEX IF NOT EXISTS idx_http_traffic_client ON specus_http_traffic_exchange (client_id);
CREATE INDEX IF NOT EXISTS idx_http_traffic_route ON specus_http_traffic_exchange (route);
CREATE INDEX IF NOT EXISTS idx_http_traffic_body_type ON specus_http_traffic_exchange (response_body_type);
CREATE INDEX IF NOT EXISTS idx_http_traffic_captured_at ON specus_http_traffic_exchange (captured_at);

CREATE TABLE IF NOT EXISTS specus_tcp_traffic_frame (
  id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
  tenant_id VARCHAR(80) NOT NULL,
  client_id BIGINT NOT NULL,
  client_name VARCHAR(120) NOT NULL,
  listen_port INTEGER NOT NULL,
  resource_id BIGINT,
  resource_name VARCHAR(255),
  channel_id VARCHAR(120) NOT NULL,
  frame_direction VARCHAR(32) NOT NULL,
  remote_address VARCHAR(255),
  source_address VARCHAR(255),
  source_port INTEGER,
  destination_address VARCHAR(255),
  destination_port INTEGER,
  stream_offset BIGINT NOT NULL,
  stream_end_offset BIGINT NOT NULL,
  frame_index BIGINT NOT NULL,
  payload_bytes BIGINT NOT NULL,
  payload_data BYTEA NOT NULL,
  payload_preview_hex VARCHAR(4096),
  payload_preview_text VARCHAR(4096),
  truncated SMALLINT NOT NULL,
  frame_time VARCHAR(40) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_tcp_traffic_tenant ON specus_tcp_traffic_frame (tenant_id);
CREATE INDEX IF NOT EXISTS idx_tcp_traffic_client ON specus_tcp_traffic_frame (client_id);
CREATE INDEX IF NOT EXISTS idx_tcp_traffic_listen_port ON specus_tcp_traffic_frame (listen_port);
CREATE INDEX IF NOT EXISTS idx_tcp_traffic_channel ON specus_tcp_traffic_frame (channel_id);
CREATE INDEX IF NOT EXISTS idx_tcp_traffic_stream ON specus_tcp_traffic_frame (tenant_id, channel_id, frame_direction, stream_offset);
CREATE INDEX IF NOT EXISTS idx_tcp_traffic_frame_time ON specus_tcp_traffic_frame (frame_time);

CREATE TABLE IF NOT EXISTS peer_mesh_device (
  id BIGINT PRIMARY KEY,
  tenant_id VARCHAR(80) NOT NULL,
  owner_username VARCHAR(80) NOT NULL,
  client_id BIGINT NOT NULL,
  client_name VARCHAR(120) NOT NULL,
  virtual_ip VARCHAR(64) NOT NULL,
  cidr VARCHAR(64) NOT NULL,
  public_key VARCHAR(256),
  nat_type VARCHAR(80),
  nat_mapping_behavior VARCHAR(80),
  nat_filtering_behavior VARCHAR(80),
  nat_behavior_discovery VARCHAR(40),
  last_endpoint VARCHAR(255),
  virtual_device_mode VARCHAR(80),
  virtual_device_name VARCHAR(80),
  virtual_device_status VARCHAR(80),
  virtual_device_error VARCHAR(512),
  virtual_device_updated_at VARCHAR(40),
  enabled SMALLINT NOT NULL DEFAULT 0,
  last_seen_at VARCHAR(40),
  created_at VARCHAR(40) NOT NULL,
  updated_at VARCHAR(40) NOT NULL,
  UNIQUE (tenant_id, client_id),
  UNIQUE (tenant_id, virtual_ip)
);

CREATE INDEX IF NOT EXISTS idx_peer_mesh_device_owner ON peer_mesh_device (tenant_id, owner_username);
CREATE INDEX IF NOT EXISTS idx_peer_mesh_device_client_name ON peer_mesh_device (client_name);

CREATE TABLE IF NOT EXISTS peer_mesh_acl (
  id BIGINT PRIMARY KEY,
  tenant_id VARCHAR(80) NOT NULL,
  owner_username VARCHAR(80) NOT NULL,
  source_client_id BIGINT NOT NULL,
  source_client_name VARCHAR(120) NOT NULL,
  target_client_id BIGINT NOT NULL,
  target_client_name VARCHAR(120) NOT NULL,
  allowed SMALLINT NOT NULL DEFAULT 1,
  direction VARCHAR(16) NOT NULL DEFAULT 'OUTBOUND',
  created_at VARCHAR(40) NOT NULL,
  updated_at VARCHAR(40) NOT NULL,
  UNIQUE (tenant_id, source_client_id, target_client_id)
);

CREATE INDEX IF NOT EXISTS idx_peer_mesh_acl_source ON peer_mesh_acl (tenant_id, source_client_id);
CREATE INDEX IF NOT EXISTS idx_peer_mesh_acl_target ON peer_mesh_acl (tenant_id, target_client_id);

CREATE TABLE IF NOT EXISTS peer_mesh_session (
  id BIGINT PRIMARY KEY,
  tenant_id VARCHAR(80) NOT NULL,
  source_client_id BIGINT NOT NULL,
  source_client_name VARCHAR(120) NOT NULL,
  target_client_id BIGINT NOT NULL,
  target_client_name VARCHAR(120) NOT NULL,
  path_type VARCHAR(40) NOT NULL,
  status VARCHAR(40) NOT NULL,
  token_hash VARCHAR(64),
  started_at VARCHAR(40) NOT NULL,
  updated_at VARCHAR(40) NOT NULL,
  expires_at VARCHAR(40) NOT NULL,
  closed_at VARCHAR(40),
  rtt_millis BIGINT,
  local_endpoint VARCHAR(255),
  remote_endpoint VARCHAR(255),
  direct_bytes BIGINT NOT NULL DEFAULT 0,
  relay_bytes BIGINT NOT NULL DEFAULT 0,
  last_traffic_at VARCHAR(40)
);

CREATE INDEX IF NOT EXISTS idx_peer_mesh_session_tenant ON peer_mesh_session (tenant_id);
CREATE INDEX IF NOT EXISTS idx_peer_mesh_session_source ON peer_mesh_session (tenant_id, source_client_id);
CREATE INDEX IF NOT EXISTS idx_peer_mesh_session_target ON peer_mesh_session (tenant_id, target_client_id);
CREATE INDEX IF NOT EXISTS idx_peer_mesh_session_status ON peer_mesh_session (status);

CREATE TABLE IF NOT EXISTS specus_connection_stat (
  id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
  tenant_id VARCHAR(80) NOT NULL DEFAULT 'default',
  client_id BIGINT,
  client_name VARCHAR(120) NOT NULL,
  stat_month VARCHAR(7) NOT NULL,
  total_count BIGINT NOT NULL,
  success_count BIGINT NOT NULL,
  failure_count BIGINT NOT NULL,
  updated_at VARCHAR(40) NOT NULL,
  UNIQUE (tenant_id, client_name, stat_month)
);

CREATE INDEX IF NOT EXISTS idx_stat_tenant ON specus_connection_stat (tenant_id);
CREATE INDEX IF NOT EXISTS idx_stat_client_name ON specus_connection_stat (client_name);

-- Public transfer rooms (Batch 5, aligned with the Java management model).
CREATE TABLE IF NOT EXISTS public_transfer_room (
  id BIGINT PRIMARY KEY,
  room_name VARCHAR(120) NOT NULL,
  owner_token_hash VARCHAR(64) NOT NULL,
  created_by_peer_id VARCHAR(120) NOT NULL,
  created_at VARCHAR(40) NOT NULL,
  updated_at VARCHAR(40) NOT NULL,
  UNIQUE (room_name, owner_token_hash)
);

CREATE INDEX IF NOT EXISTS idx_public_transfer_room_name ON public_transfer_room (room_name);

CREATE TABLE IF NOT EXISTS public_transfer_room_access (
  id BIGINT PRIMARY KEY,
  room_id BIGINT NOT NULL,
  token_hash VARCHAR(64) NOT NULL,
  role VARCHAR(16) NOT NULL,
  label VARCHAR(80) NOT NULL,
  created_at VARCHAR(40) NOT NULL,
  expires_at VARCHAR(40),
  revoked_at VARCHAR(40),
  UNIQUE (token_hash)
);

CREATE INDEX IF NOT EXISTS idx_public_transfer_access_room ON public_transfer_room_access (room_id);

CREATE TABLE IF NOT EXISTS public_transfer_room_pairing_code (
  id BIGINT PRIMARY KEY,
  room_id BIGINT NOT NULL,
  code_hash VARCHAR(64) NOT NULL,
  role VARCHAR(16) NOT NULL,
  label VARCHAR(80) NOT NULL,
  created_at VARCHAR(40) NOT NULL,
  expires_at VARCHAR(40) NOT NULL,
  max_uses BIGINT NOT NULL,
  used_count BIGINT NOT NULL,
  revoked_at VARCHAR(40),
  UNIQUE (code_hash)
);

CREATE INDEX IF NOT EXISTS idx_public_transfer_pairing_room ON public_transfer_room_pairing_code (room_id);

CREATE TABLE IF NOT EXISTS public_transfer_diagram_version (
  id BIGINT PRIMARY KEY,
  room_id BIGINT NOT NULL,
  name VARCHAR(80) NOT NULL,
  author_peer_id VARCHAR(120) NOT NULL,
  snapshot_data BYTEA NOT NULL,
  size_bytes BIGINT NOT NULL,
  created_at VARCHAR(40) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_public_transfer_version_room ON public_transfer_diagram_version (room_id);
CREATE INDEX IF NOT EXISTS idx_public_transfer_version_created ON public_transfer_diagram_version (created_at);

CREATE TABLE IF NOT EXISTS user_diagram_document (
  id BIGINT PRIMARY KEY,
  tenant_id VARCHAR(80) NOT NULL,
  owner_username VARCHAR(160) NOT NULL,
  name VARCHAR(120) NOT NULL,
  snapshot_data BYTEA NOT NULL,
  size_bytes BIGINT NOT NULL,
  revision BIGINT NOT NULL DEFAULT 0,
  created_at VARCHAR(40) NOT NULL,
  updated_at VARCHAR(40) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_user_diagram_owner ON user_diagram_document (tenant_id, owner_username);
CREATE INDEX IF NOT EXISTS idx_user_diagram_updated ON user_diagram_document (updated_at);
