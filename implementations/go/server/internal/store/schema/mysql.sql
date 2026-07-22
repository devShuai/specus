CREATE TABLE IF NOT EXISTS tunnel_client_account (
  id BIGINT NOT NULL PRIMARY KEY,
  tenant_id VARCHAR(80) NOT NULL DEFAULT 'default',
  owner_username VARCHAR(80),
  client_name VARCHAR(120) NOT NULL,
  password_hash VARCHAR(64) NOT NULL,
  enabled TINYINT(1) NOT NULL,
  connection_rate_limit_per_minute INT NOT NULL,
  created_at VARCHAR(40) NOT NULL,
  updated_at VARCHAR(40) NOT NULL,
  UNIQUE KEY uq_client_account_name (client_name),
  KEY idx_tunnel_client_tenant (tenant_id),
  KEY idx_tunnel_client_owner (tenant_id, owner_username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS tunnel_client_credential (
  id BIGINT NOT NULL PRIMARY KEY,
  tenant_id VARCHAR(80) NOT NULL,
  owner_username VARCHAR(80),
  api_key VARCHAR(120) NOT NULL,
  secret_hash VARCHAR(64) NOT NULL,
  enabled TINYINT(1) NOT NULL,
  max_online_instances INT NOT NULL,
  created_at VARCHAR(40) NOT NULL,
  updated_at VARCHAR(40) NOT NULL,
  UNIQUE KEY uk_client_credential_api_key (api_key),
  KEY idx_client_credential_tenant (tenant_id),
  KEY idx_client_credential_owner (tenant_id, owner_username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS tunnel_client_auth_nonce (
  api_key_hash VARCHAR(64) NOT NULL,
  nonce_hash VARCHAR(64) NOT NULL,
  expires_at VARCHAR(40) NOT NULL,
  created_at VARCHAR(40) NOT NULL,
  PRIMARY KEY (api_key_hash, nonce_hash),
  KEY idx_client_auth_nonce_expiry (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS tunnel_websocket_ticket (
  token_hash VARCHAR(64) NOT NULL PRIMARY KEY,
  scope VARCHAR(40) NOT NULL,
  username VARCHAR(80),
  tenant_id VARCHAR(80),
  is_admin TINYINT(1) NOT NULL DEFAULT 0,
  room_id VARCHAR(120),
  room_key VARCHAR(80),
  room_role VARCHAR(16),
  peer_id VARCHAR(120),
  display_name VARCHAR(120),
  shared_room TINYINT(1) NOT NULL DEFAULT 0,
  remote_address_hash VARCHAR(64) NOT NULL,
  created_at VARCHAR(40) NOT NULL,
  expires_at VARCHAR(40) NOT NULL,
  KEY idx_websocket_ticket_expiry (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS tunnel_client_identity (
  id BIGINT NOT NULL PRIMARY KEY,
  tenant_id VARCHAR(80) NOT NULL,
  credential_id BIGINT NOT NULL,
  client_id BIGINT NOT NULL,
  client_name VARCHAR(120) NOT NULL,
  machine_fingerprint VARCHAR(160) NOT NULL,
  os_user VARCHAR(120) NOT NULL,
  hostname VARCHAR(160),
  first_seen_at VARCHAR(40) NOT NULL,
  last_seen_at VARCHAR(40) NOT NULL,
  UNIQUE KEY uk_client_identity_machine_user (credential_id, machine_fingerprint, os_user),
  KEY idx_client_identity_tenant (tenant_id),
  KEY idx_client_identity_client (client_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS tunnel_client_session (
  id BIGINT NOT NULL PRIMARY KEY,
  tenant_id VARCHAR(80) NOT NULL,
  credential_id BIGINT NOT NULL,
  identity_id BIGINT NOT NULL,
  client_id BIGINT NOT NULL,
  client_name VARCHAR(120) NOT NULL,
  token_hash VARCHAR(64) NOT NULL,
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
  message_send_capable TINYINT(1) NOT NULL DEFAULT 0,
  message_receive_capable TINYINT(1) NOT NULL DEFAULT 0,
  message_attachments_capable TINYINT(1) NOT NULL DEFAULT 0,
  message_media_preview_capable TINYINT(1) NOT NULL DEFAULT 0,
  message_max_attachment_bytes BIGINT NOT NULL DEFAULT 0,
  http_login_at VARCHAR(40) NOT NULL,
  netty_connected_at VARCHAR(40),
  disconnected_at VARCHAR(40),
  expires_at VARCHAR(40) NOT NULL,
  channel_id VARCHAR(160),
  remote_address VARCHAR(255),
  UNIQUE KEY uk_client_session_token (token_hash),
  KEY idx_client_session_token (token_hash),
  KEY idx_client_session_credential_status (credential_id, status),
  KEY idx_client_session_machine_status (credential_id, machine_fingerprint, os_user, status),
  KEY idx_client_session_client_status (client_id, status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS tunnel_management_user (
  username VARCHAR(80) NOT NULL PRIMARY KEY,
  tenant_id VARCHAR(80) NOT NULL,
  password_hash VARCHAR(64) NOT NULL,
  role VARCHAR(20) NOT NULL,
  enabled TINYINT(1) NOT NULL,
  created_at VARCHAR(40) NOT NULL,
  updated_at VARCHAR(40) NOT NULL,
  KEY idx_management_user_tenant (tenant_id),
  KEY idx_management_user_role (role)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS tunnel_management_user_email (
  username VARCHAR(80) NOT NULL PRIMARY KEY,
  email VARCHAR(254) NOT NULL UNIQUE,
  verified_at VARCHAR(40) NOT NULL,
  created_at VARCHAR(40) NOT NULL,
  updated_at VARCHAR(40) NOT NULL,
  KEY idx_management_user_email_verified (verified_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS tunnel_management_registration_challenge (
  registration_id VARCHAR(64) NOT NULL PRIMARY KEY,
  username VARCHAR(80) NOT NULL,
  email VARCHAR(254) NOT NULL,
  password_hash VARCHAR(64) NOT NULL,
  code_hash VARCHAR(64) NOT NULL,
  attempts_remaining INT NOT NULL,
  expires_at VARCHAR(40) NOT NULL,
  resend_available_at VARCHAR(40) NOT NULL,
  created_at VARCHAR(40) NOT NULL,
  updated_at VARCHAR(40) NOT NULL,
  KEY idx_registration_challenge_username (username),
  KEY idx_registration_challenge_email (email),
	UNIQUE KEY uq_registration_challenge_username (username),
	UNIQUE KEY uq_registration_challenge_email (email),
  KEY idx_registration_challenge_expiry (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS client_download_link (
  id BIGINT NOT NULL PRIMARY KEY,
  implementation VARCHAR(32) NOT NULL,
  platform VARCHAR(32) NOT NULL,
  arch VARCHAR(32) NOT NULL,
  display_name VARCHAR(120) NOT NULL,
  download_url VARCHAR(1024) NOT NULL,
  description VARCHAR(512),
  display_order INT NOT NULL DEFAULT 0,
  enabled TINYINT(1) NOT NULL DEFAULT 1,
  created_at VARCHAR(40) NOT NULL,
  updated_at VARCHAR(40) NOT NULL,
  KEY idx_client_download_impl (implementation),
  KEY idx_client_download_order (display_order)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS transfer_attachment (
  id BIGINT NOT NULL PRIMARY KEY,
  tenant_id VARCHAR(80),
  scope VARCHAR(40) NOT NULL,
  room_id VARCHAR(120),
  room_token_hash VARCHAR(64),
  owner_username VARCHAR(80),
  target_client_id BIGINT,
  object_key VARCHAR(512) NOT NULL,
  file_name VARCHAR(255) NOT NULL,
  mime_type VARCHAR(120) NOT NULL,
  size_bytes BIGINT NOT NULL,
  sha256 VARCHAR(64),
  status VARCHAR(24) NOT NULL,
  created_at VARCHAR(40) NOT NULL,
  updated_at VARCHAR(40) NOT NULL,
  upload_expires_at VARCHAR(40) NOT NULL,
  expires_at VARCHAR(40) NOT NULL,
  uploaded_at VARCHAR(40),
  UNIQUE KEY uk_transfer_attachment_object_key (object_key),
  KEY idx_transfer_attachment_tenant (tenant_id, scope, id),
  KEY idx_transfer_attachment_room (scope, room_id, id),
  KEY idx_transfer_attachment_owner_status (tenant_id, owner_username, status, expires_at),
  KEY idx_transfer_attachment_expires (expires_at, status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS transfer_attachment_download_usage (
  id BIGINT NOT NULL PRIMARY KEY,
  tenant_id VARCHAR(80) NOT NULL,
  username VARCHAR(80) NOT NULL,
  attachment_id BIGINT NOT NULL,
  size_bytes BIGINT NOT NULL,
  usage_month VARCHAR(7) NOT NULL,
  created_at VARCHAR(40) NOT NULL,
  KEY idx_attachment_download_usage_account_month (tenant_id, username, usage_month),
  KEY idx_attachment_download_usage_attachment (attachment_id, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS transfer_attachment_download_grant (
  id BIGINT NOT NULL PRIMARY KEY,
  token_hash VARCHAR(64) NOT NULL,
  tenant_id VARCHAR(80) NOT NULL,
  username VARCHAR(120) NOT NULL,
  attachment_id BIGINT NOT NULL,
  created_at VARCHAR(64) NOT NULL,
  expires_at VARCHAR(64) NOT NULL,
  consumed_at VARCHAR(64),
  UNIQUE KEY uk_attachment_download_grant_token (token_hash),
  KEY idx_attachment_download_grant_attachment (attachment_id, created_at),
  KEY idx_attachment_download_grant_expiry (expires_at, consumed_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS tunnel_connection_record (
  id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  tenant_id VARCHAR(80),
  client_id BIGINT,
  client_name VARCHAR(120) NOT NULL,
  channel_id VARCHAR(160),
  remote_address VARCHAR(255),
  connected_at VARCHAR(40) NOT NULL,
  disconnected_at VARCHAR(40),
  success TINYINT(1) NOT NULL,
  failure_reason VARCHAR(255),
  disconnect_reason VARCHAR(40),
  KEY idx_tunnel_connection_tenant (tenant_id),
  KEY idx_tunnel_connection_client_time (client_id, connected_at),
  KEY idx_tunnel_connection_connected_at (connected_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS tunnel_mapping (
  id BIGINT NOT NULL PRIMARY KEY,
  tenant_id VARCHAR(80) NOT NULL,
  client_id BIGINT NOT NULL,
  client_name VARCHAR(120) NOT NULL,
  listen_port INT NOT NULL,
  target_address VARCHAR(255) NOT NULL,
  target_port INT NOT NULL,
  enabled TINYINT(1) NOT NULL,
  detail_capture_enabled TINYINT(1) NOT NULL DEFAULT 0,
  created_at VARCHAR(40) NOT NULL,
  updated_at VARCHAR(40) NOT NULL,
  UNIQUE KEY uq_tunnel_mapping_listen_port (listen_port),
  KEY idx_tunnel_mapping_client_id (client_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS http_route_mapping (
  id BIGINT NOT NULL PRIMARY KEY,
  tenant_id VARCHAR(80) NOT NULL,
  client_id BIGINT NOT NULL,
  client_name VARCHAR(120) NOT NULL,
  route VARCHAR(60) NOT NULL,
  target_base_url VARCHAR(512) NOT NULL,
  enabled TINYINT(1) NOT NULL,
  detail_capture_enabled TINYINT(1) NOT NULL DEFAULT 0,
  path_rewrite_enabled TINYINT(1) NOT NULL DEFAULT 0,
  created_at VARCHAR(40) NOT NULL,
  updated_at VARCHAR(40) NOT NULL,
  UNIQUE KEY uq_http_route_client_route (client_id, route),
  KEY idx_http_route_client_id (client_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS tunnel_traffic_usage (
  id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  tenant_id VARCHAR(80),
  client_id BIGINT NOT NULL,
  client_name VARCHAR(120) NOT NULL,
  usage_date VARCHAR(10) NOT NULL,
  upload_bytes BIGINT NOT NULL,
  download_bytes BIGINT NOT NULL,
  updated_at VARCHAR(40) NOT NULL,
  UNIQUE KEY uq_traffic_client_date (client_id, usage_date),
  KEY idx_tunnel_traffic_tenant (tenant_id),
  KEY idx_traffic_client_id (client_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS tunnel_resource_traffic_usage (
  id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  tenant_id VARCHAR(80) NOT NULL,
  client_id BIGINT NOT NULL,
  client_name VARCHAR(120) NOT NULL,
  resource_type VARCHAR(32) NOT NULL,
  resource_key VARCHAR(128) NOT NULL,
  resource_id BIGINT,
  resource_name VARCHAR(255) NOT NULL,
  usage_date VARCHAR(10) NOT NULL,
  upload_bytes BIGINT NOT NULL,
  download_bytes BIGINT NOT NULL,
  updated_at VARCHAR(40) NOT NULL,
  UNIQUE KEY uk_resource_traffic_resource_date (tenant_id, client_id, resource_type, resource_key, usage_date),
  KEY idx_resource_traffic_tenant (tenant_id),
  KEY idx_resource_traffic_client (client_id),
  KEY idx_resource_traffic_type (resource_type),
  KEY idx_resource_traffic_date (usage_date)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS tunnel_http_traffic_exchange (
  id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  tenant_id VARCHAR(80) NOT NULL,
  client_id BIGINT NOT NULL,
  client_name VARCHAR(120) NOT NULL,
  route VARCHAR(128) NOT NULL,
  resource_id BIGINT,
  resource_name VARCHAR(255),
  method VARCHAR(16),
  relative_path VARCHAR(1024),
  raw_query VARCHAR(2048),
  status_code INT NOT NULL,
  success TINYINT(1) NOT NULL,
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
  request_preview_text LONGTEXT,
  response_preview_hex VARCHAR(4096),
  response_preview_text LONGTEXT,
  request_truncated TINYINT(1) NOT NULL,
  response_truncated TINYINT(1) NOT NULL,
  captured_at VARCHAR(40) NOT NULL,
  KEY idx_http_traffic_tenant (tenant_id),
  KEY idx_http_traffic_client (client_id),
  KEY idx_http_traffic_route (route),
  KEY idx_http_traffic_body_type (response_body_type),
  KEY idx_http_traffic_captured_at (captured_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS tunnel_tcp_traffic_frame (
  id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  tenant_id VARCHAR(80) NOT NULL,
  client_id BIGINT NOT NULL,
  client_name VARCHAR(120) NOT NULL,
  listen_port INT NOT NULL,
  resource_id BIGINT,
  resource_name VARCHAR(255),
  channel_id VARCHAR(120) NOT NULL,
  frame_direction VARCHAR(32) NOT NULL,
  remote_address VARCHAR(255),
  source_address VARCHAR(255),
  source_port INT,
  destination_address VARCHAR(255),
  destination_port INT,
  stream_offset BIGINT NOT NULL,
  stream_end_offset BIGINT NOT NULL,
  frame_index BIGINT NOT NULL,
  payload_bytes BIGINT NOT NULL,
  payload_data LONGBLOB NOT NULL,
  payload_preview_hex VARCHAR(4096),
  payload_preview_text VARCHAR(4096),
  truncated TINYINT(1) NOT NULL,
  frame_time VARCHAR(40) NOT NULL,
  KEY idx_tcp_traffic_tenant (tenant_id),
  KEY idx_tcp_traffic_client (client_id),
  KEY idx_tcp_traffic_listen_port (listen_port),
  KEY idx_tcp_traffic_channel (channel_id),
  KEY idx_tcp_traffic_stream (tenant_id, channel_id, frame_direction, stream_offset),
  KEY idx_tcp_traffic_frame_time (frame_time)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS peer_mesh_device (
  id BIGINT NOT NULL PRIMARY KEY,
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
  enabled TINYINT(1) NOT NULL DEFAULT 0,
  last_seen_at VARCHAR(40),
  created_at VARCHAR(40) NOT NULL,
  updated_at VARCHAR(40) NOT NULL,
  UNIQUE KEY uk_peer_mesh_device_client (tenant_id, client_id),
  UNIQUE KEY uk_peer_mesh_device_ip (tenant_id, virtual_ip),
  KEY idx_peer_mesh_device_owner (tenant_id, owner_username),
  KEY idx_peer_mesh_device_client_name (client_name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS peer_mesh_acl (
  id BIGINT NOT NULL PRIMARY KEY,
  tenant_id VARCHAR(80) NOT NULL,
  owner_username VARCHAR(80) NOT NULL,
  source_client_id BIGINT NOT NULL,
  source_client_name VARCHAR(120) NOT NULL,
  target_client_id BIGINT NOT NULL,
  target_client_name VARCHAR(120) NOT NULL,
  allowed TINYINT(1) NOT NULL DEFAULT 1,
  direction VARCHAR(16) NOT NULL DEFAULT 'OUTBOUND',
  created_at VARCHAR(40) NOT NULL,
  updated_at VARCHAR(40) NOT NULL,
  UNIQUE KEY uk_peer_mesh_acl_pair (tenant_id, source_client_id, target_client_id),
  KEY idx_peer_mesh_acl_source (tenant_id, source_client_id),
  KEY idx_peer_mesh_acl_target (tenant_id, target_client_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS peer_mesh_session (
  id BIGINT NOT NULL PRIMARY KEY,
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
  last_traffic_at VARCHAR(40),
  KEY idx_peer_mesh_session_tenant (tenant_id),
  KEY idx_peer_mesh_session_source (tenant_id, source_client_id),
  KEY idx_peer_mesh_session_target (tenant_id, target_client_id),
  KEY idx_peer_mesh_session_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS tunnel_connection_stat (
  id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  tenant_id VARCHAR(80) NOT NULL DEFAULT 'default',
  client_id BIGINT,
  client_name VARCHAR(120) NOT NULL,
  stat_month VARCHAR(7) NOT NULL,
  total_count BIGINT NOT NULL,
  success_count BIGINT NOT NULL,
  failure_count BIGINT NOT NULL,
  updated_at VARCHAR(40) NOT NULL,
  UNIQUE KEY uq_stat_client_month (tenant_id, client_name, stat_month),
  KEY idx_stat_tenant (tenant_id),
  KEY idx_stat_client_name (client_name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Public transfer rooms (Batch 5, aligned with the Java management model).
CREATE TABLE IF NOT EXISTS public_transfer_room (
  id BIGINT NOT NULL PRIMARY KEY,
  room_name VARCHAR(120) NOT NULL,
  owner_token_hash VARCHAR(64) NOT NULL,
  created_by_peer_id VARCHAR(120) NOT NULL,
  created_at VARCHAR(40) NOT NULL,
  updated_at VARCHAR(40) NOT NULL,
  UNIQUE KEY uk_public_transfer_room_key (room_name, owner_token_hash),
  KEY idx_public_transfer_room_name (room_name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS public_transfer_room_access (
  id BIGINT NOT NULL PRIMARY KEY,
  room_id BIGINT NOT NULL,
  token_hash VARCHAR(64) NOT NULL,
  role VARCHAR(16) NOT NULL,
  label VARCHAR(80) NOT NULL,
  created_at VARCHAR(40) NOT NULL,
  expires_at VARCHAR(40),
  revoked_at VARCHAR(40),
  UNIQUE KEY uk_public_transfer_access_token (token_hash),
  KEY idx_public_transfer_access_room (room_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS public_transfer_room_pairing_code (
  id BIGINT NOT NULL PRIMARY KEY,
  room_id BIGINT NOT NULL,
  code_hash VARCHAR(64) NOT NULL,
  role VARCHAR(16) NOT NULL,
  label VARCHAR(80) NOT NULL,
  created_at VARCHAR(40) NOT NULL,
  expires_at VARCHAR(40) NOT NULL,
  max_uses INT NOT NULL,
  used_count INT NOT NULL,
  revoked_at VARCHAR(40),
  UNIQUE KEY uk_public_transfer_pairing_code_hash (code_hash),
  KEY idx_public_transfer_pairing_room (room_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS public_transfer_diagram_version (
  id BIGINT NOT NULL PRIMARY KEY,
  room_id BIGINT NOT NULL,
  name VARCHAR(80) NOT NULL,
  author_peer_id VARCHAR(120) NOT NULL,
  snapshot_data LONGBLOB NOT NULL,
  size_bytes BIGINT NOT NULL,
  created_at VARCHAR(40) NOT NULL,
  KEY idx_public_transfer_version_room (room_id),
  KEY idx_public_transfer_version_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS user_diagram_document (
  id BIGINT NOT NULL PRIMARY KEY,
  tenant_id VARCHAR(80) NOT NULL,
  owner_username VARCHAR(160) NOT NULL,
  name VARCHAR(120) NOT NULL,
  snapshot_data LONGBLOB NOT NULL,
  size_bytes BIGINT NOT NULL,
  revision BIGINT NOT NULL DEFAULT 0,
  created_at VARCHAR(40) NOT NULL,
  updated_at VARCHAR(40) NOT NULL,
  KEY idx_user_diagram_owner (tenant_id, owner_username),
  KEY idx_user_diagram_updated (updated_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
