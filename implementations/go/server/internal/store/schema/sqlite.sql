CREATE TABLE IF NOT EXISTS specus_client_account (
  id INTEGER PRIMARY KEY,
  tenant_id TEXT NOT NULL DEFAULT 'default',
  owner_username TEXT,
  client_name TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  enabled INTEGER NOT NULL,
  connection_rate_limit_per_minute INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_specus_client_tenant ON specus_client_account (tenant_id);
CREATE INDEX IF NOT EXISTS idx_specus_client_owner ON specus_client_account (tenant_id, owner_username);

CREATE TABLE IF NOT EXISTS specus_client_credential (
  id INTEGER PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  owner_username TEXT,
  api_key TEXT NOT NULL UNIQUE,
  secret_hash TEXT NOT NULL,
  enabled INTEGER NOT NULL,
  max_online_instances INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_client_credential_tenant ON specus_client_credential (tenant_id);
CREATE INDEX IF NOT EXISTS idx_client_credential_owner ON specus_client_credential (tenant_id, owner_username);

CREATE TABLE IF NOT EXISTS specus_client_auth_nonce (
  id TEXT PRIMARY KEY,
  api_key_hash TEXT NOT NULL,
  expires_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_client_auth_nonce_expires ON specus_client_auth_nonce (expires_at);

CREATE TABLE IF NOT EXISTS specus_websocket_ticket (
  token_hash TEXT PRIMARY KEY,
  scope TEXT NOT NULL,
  attributes_json TEXT NOT NULL,
  username TEXT,
  tenant_id TEXT,
  is_admin INTEGER NOT NULL DEFAULT 0,
  room_id TEXT,
  room_key TEXT,
  room_role TEXT,
  peer_id TEXT,
  display_name TEXT,
  shared_room INTEGER NOT NULL DEFAULT 0,
  remote_address_hash TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_websocket_ticket_expiry ON specus_websocket_ticket (expires_at);

CREATE TABLE IF NOT EXISTS specus_client_identity (
  id INTEGER PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  credential_id INTEGER NOT NULL,
  client_id INTEGER NOT NULL,
  client_name TEXT NOT NULL,
  machine_fingerprint TEXT NOT NULL,
  os_user TEXT NOT NULL,
  hostname TEXT,
  first_seen_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  UNIQUE (credential_id, machine_fingerprint, os_user)
);

CREATE INDEX IF NOT EXISTS idx_client_identity_tenant ON specus_client_identity (tenant_id);
CREATE INDEX IF NOT EXISTS idx_client_identity_client ON specus_client_identity (client_id);

CREATE TABLE IF NOT EXISTS specus_client_session (
  id INTEGER PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  credential_id INTEGER NOT NULL,
  identity_id INTEGER NOT NULL,
  client_id INTEGER NOT NULL,
  client_name TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL,
  machine_fingerprint TEXT NOT NULL,
  os_user TEXT NOT NULL,
  hostname TEXT,
  os_name TEXT,
  os_version TEXT,
  os_arch TEXT,
  client_version TEXT,
  java_version TEXT,
  local_addresses TEXT,
  message_send_capable INTEGER NOT NULL DEFAULT 0,
  message_receive_capable INTEGER NOT NULL DEFAULT 0,
  message_attachments_capable INTEGER NOT NULL DEFAULT 0,
  message_media_preview_capable INTEGER NOT NULL DEFAULT 0,
  message_max_attachment_bytes INTEGER NOT NULL DEFAULT 0,
  http_login_at TEXT NOT NULL,
  netty_connected_at TEXT,
  disconnected_at TEXT,
  expires_at TEXT NOT NULL,
  channel_id TEXT,
  remote_address TEXT
);

CREATE INDEX IF NOT EXISTS idx_client_session_token ON specus_client_session (token_hash);
CREATE INDEX IF NOT EXISTS idx_client_session_credential_status ON specus_client_session (credential_id, status);
CREATE INDEX IF NOT EXISTS idx_client_session_machine_status ON specus_client_session (credential_id, machine_fingerprint, os_user, status);
CREATE INDEX IF NOT EXISTS idx_client_session_client_status ON specus_client_session (client_id, status);

CREATE TABLE IF NOT EXISTS specus_management_user (
  username TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  oidc_issuer TEXT,
  oidc_subject TEXT,
  oidc_identity_key TEXT,
  role TEXT NOT NULL,
  enabled INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_management_user_tenant ON specus_management_user (tenant_id);
CREATE INDEX IF NOT EXISTS idx_management_user_role ON specus_management_user (role);

CREATE TABLE IF NOT EXISTS specus_management_user_email (
  username TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  verified_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_management_user_email_verified ON specus_management_user_email (verified_at);

CREATE TABLE IF NOT EXISTS specus_management_registration_challenge (
  registration_id TEXT PRIMARY KEY,
  username TEXT NOT NULL,
  email TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  code_hash TEXT NOT NULL,
  attempts_remaining INTEGER NOT NULL,
  expires_at TEXT NOT NULL,
  resend_available_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_registration_challenge_username ON specus_management_registration_challenge (username COLLATE NOCASE);
CREATE UNIQUE INDEX IF NOT EXISTS uq_registration_challenge_email ON specus_management_registration_challenge (email COLLATE NOCASE);

CREATE INDEX IF NOT EXISTS idx_registration_challenge_username ON specus_management_registration_challenge (username);
CREATE INDEX IF NOT EXISTS idx_registration_challenge_email ON specus_management_registration_challenge (email);
CREATE INDEX IF NOT EXISTS idx_registration_challenge_expiry ON specus_management_registration_challenge (expires_at);

CREATE TABLE IF NOT EXISTS client_download_link (
  id INTEGER PRIMARY KEY,
  implementation TEXT NOT NULL,
  platform TEXT NOT NULL,
  arch TEXT NOT NULL,
  display_name TEXT NOT NULL,
  download_url TEXT NOT NULL,
  description TEXT,
  display_order INTEGER NOT NULL DEFAULT 0,
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_client_download_impl ON client_download_link (implementation);
CREATE INDEX IF NOT EXISTS idx_client_download_order ON client_download_link (display_order);

CREATE TABLE IF NOT EXISTS transfer_attachment (
  id INTEGER PRIMARY KEY,
  tenant_id TEXT,
  scope TEXT NOT NULL,
  room_id TEXT,
  room_token_hash TEXT,
  public_transfer_room_id INTEGER,
  owner_username TEXT,
  target_client_id INTEGER,
  object_key TEXT NOT NULL UNIQUE,
  file_name TEXT NOT NULL,
  mime_type TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  sha256 TEXT,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  upload_expires_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  uploaded_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_transfer_attachment_tenant ON transfer_attachment (tenant_id, scope, id);
CREATE INDEX IF NOT EXISTS idx_transfer_attachment_room ON transfer_attachment (scope, room_id, id);
CREATE INDEX IF NOT EXISTS idx_transfer_attachment_owner_status ON transfer_attachment (tenant_id, owner_username, status, expires_at);
CREATE INDEX IF NOT EXISTS idx_transfer_attachment_expires ON transfer_attachment (expires_at, status);

CREATE TABLE IF NOT EXISTS transfer_attachment_download_usage (
  id INTEGER PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  username TEXT NOT NULL,
  attachment_id INTEGER NOT NULL,
  size_bytes INTEGER NOT NULL,
  usage_month TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_attachment_download_usage_account_month
  ON transfer_attachment_download_usage (tenant_id, username, usage_month);
CREATE INDEX IF NOT EXISTS idx_attachment_download_usage_attachment
  ON transfer_attachment_download_usage (attachment_id, created_at);

CREATE TABLE IF NOT EXISTS transfer_attachment_download_grant (
  id INTEGER PRIMARY KEY,
  token_hash TEXT NOT NULL UNIQUE,
  tenant_id TEXT NOT NULL,
  username TEXT NOT NULL,
  attachment_id INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  consumed_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_attachment_download_grant_attachment
  ON transfer_attachment_download_grant (attachment_id, created_at);
CREATE INDEX IF NOT EXISTS idx_attachment_download_grant_expiry
  ON transfer_attachment_download_grant (expires_at, consumed_at);

CREATE TABLE IF NOT EXISTS specus_connection_record (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id TEXT,
  client_id INTEGER,
  client_name TEXT NOT NULL,
  channel_id TEXT,
  remote_address TEXT,
  connected_at TEXT NOT NULL,
  disconnected_at TEXT,
  success INTEGER NOT NULL,
  failure_reason TEXT,
  disconnect_reason TEXT
);

CREATE INDEX IF NOT EXISTS idx_specus_connection_tenant ON specus_connection_record (tenant_id);
CREATE INDEX IF NOT EXISTS idx_specus_connection_client_time ON specus_connection_record (client_id, connected_at);
CREATE INDEX IF NOT EXISTS idx_specus_connection_connected_at ON specus_connection_record (connected_at);

CREATE TABLE IF NOT EXISTS specus_mapping (
  id INTEGER PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  client_id INTEGER NOT NULL,
  client_name TEXT NOT NULL,
  listen_port INTEGER NOT NULL UNIQUE,
  target_address TEXT NOT NULL,
  target_port INTEGER NOT NULL,
  enabled INTEGER NOT NULL,
  detail_capture_enabled INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_specus_mapping_client_id ON specus_mapping (client_id);

CREATE TABLE IF NOT EXISTS http_route_mapping (
  id INTEGER PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  client_id INTEGER NOT NULL,
  client_name TEXT NOT NULL,
  route TEXT NOT NULL,
  target_base_url TEXT NOT NULL,
  enabled INTEGER NOT NULL,
  detail_capture_enabled INTEGER NOT NULL DEFAULT 0,
  media_capture_enabled INTEGER NOT NULL DEFAULT 0,
  path_rewrite_enabled INTEGER NOT NULL DEFAULT 0,
  auth_enabled INTEGER NOT NULL DEFAULT 0,
  auth_username TEXT NOT NULL DEFAULT '',
  auth_password_hash TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (client_id, route)
);

CREATE INDEX IF NOT EXISTS idx_http_route_client_id ON http_route_mapping (client_id);

CREATE TABLE IF NOT EXISTS specus_http_media_capture (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id TEXT NOT NULL,
  client_id INTEGER NOT NULL,
  client_name TEXT NOT NULL,
  route TEXT NOT NULL,
  resource_id INTEGER,
  source_url TEXT NOT NULL,
  resource_key TEXT NOT NULL,
  deduplication_key TEXT UNIQUE,
  method TEXT NOT NULL,
  status_code INTEGER NOT NULL,
  content_type TEXT,
  content_encoding TEXT,
  media_kind TEXT NOT NULL,
  entity_tag TEXT,
  last_modified TEXT,
  content_range_start INTEGER,
  content_range_end INTEGER,
  total_bytes INTEGER,
  captured_bytes INTEGER NOT NULL,
  segment_sequence INTEGER,
  initialization_segment INTEGER NOT NULL DEFAULT 0,
  live_stream INTEGER NOT NULL DEFAULT 0,
  object_key TEXT NOT NULL,
  upload_id TEXT,
  object_etag TEXT,
  state TEXT NOT NULL,
  failure_reason TEXT,
  response_headers TEXT,
  captured_at TEXT NOT NULL,
  completed_at TEXT,
  expires_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_http_media_tenant_id ON specus_http_media_capture (tenant_id, id);
CREATE INDEX IF NOT EXISTS idx_http_media_tenant_client_id ON specus_http_media_capture (tenant_id, client_id, id);
CREATE INDEX IF NOT EXISTS idx_http_media_resource ON specus_http_media_capture (tenant_id, resource_key, id);
CREATE INDEX IF NOT EXISTS idx_http_media_source ON specus_http_media_capture (tenant_id, client_id, route, id);
CREATE INDEX IF NOT EXISTS idx_http_media_expiry ON specus_http_media_capture (state, expires_at);

CREATE TABLE IF NOT EXISTS specus_http_media_reference (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id TEXT NOT NULL,
  manifest_capture_id INTEGER NOT NULL,
  relation_type TEXT NOT NULL,
  sequence_index INTEGER,
  original_uri TEXT NOT NULL,
  resolved_source_url TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_http_media_ref_manifest ON specus_http_media_reference (tenant_id, manifest_capture_id, sequence_index);
CREATE INDEX IF NOT EXISTS idx_http_media_ref_source ON specus_http_media_reference (tenant_id, manifest_capture_id);

CREATE TABLE IF NOT EXISTS specus_traffic_usage (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id TEXT,
  client_id INTEGER NOT NULL,
  client_name TEXT NOT NULL,
  usage_date TEXT NOT NULL,
  upload_bytes INTEGER NOT NULL,
  download_bytes INTEGER NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (client_id, usage_date)
);

CREATE INDEX IF NOT EXISTS idx_specus_traffic_tenant ON specus_traffic_usage (tenant_id);
CREATE INDEX IF NOT EXISTS idx_traffic_client_id ON specus_traffic_usage (client_id);

CREATE TABLE IF NOT EXISTS specus_resource_traffic_usage (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id TEXT NOT NULL,
  client_id INTEGER NOT NULL,
  client_name TEXT NOT NULL,
  resource_type TEXT NOT NULL,
  resource_key TEXT NOT NULL,
  resource_id INTEGER,
  resource_name TEXT NOT NULL,
  usage_date TEXT NOT NULL,
  upload_bytes INTEGER NOT NULL,
  download_bytes INTEGER NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (tenant_id, client_id, resource_type, resource_key, usage_date)
);

CREATE INDEX IF NOT EXISTS idx_resource_traffic_tenant ON specus_resource_traffic_usage (tenant_id);
CREATE INDEX IF NOT EXISTS idx_resource_traffic_client ON specus_resource_traffic_usage (client_id);
CREATE INDEX IF NOT EXISTS idx_resource_traffic_type ON specus_resource_traffic_usage (resource_type);
CREATE INDEX IF NOT EXISTS idx_resource_traffic_date ON specus_resource_traffic_usage (usage_date);

CREATE TABLE IF NOT EXISTS specus_http_traffic_exchange (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id TEXT NOT NULL,
  client_id INTEGER NOT NULL,
  client_name TEXT NOT NULL,
  route TEXT NOT NULL,
  resource_id INTEGER,
  resource_name TEXT,
  method TEXT,
  relative_path TEXT,
  raw_query TEXT,
  status_code INTEGER NOT NULL,
  success INTEGER NOT NULL,
  error TEXT,
  remote_address TEXT,
  request_bytes INTEGER NOT NULL,
  response_bytes INTEGER NOT NULL,
  elapsed_ms INTEGER NOT NULL,
  request_content_type TEXT,
  response_content_type TEXT,
  response_body_type TEXT,
  request_headers TEXT,
  response_headers TEXT,
  request_preview_hex TEXT,
  request_preview_text TEXT,
  response_preview_hex TEXT,
  response_preview_text TEXT,
  request_truncated INTEGER NOT NULL,
  response_truncated INTEGER NOT NULL,
  captured_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_http_traffic_tenant ON specus_http_traffic_exchange (tenant_id);
CREATE INDEX IF NOT EXISTS idx_http_traffic_client ON specus_http_traffic_exchange (client_id);
CREATE INDEX IF NOT EXISTS idx_http_traffic_route ON specus_http_traffic_exchange (route);
CREATE INDEX IF NOT EXISTS idx_http_traffic_body_type ON specus_http_traffic_exchange (response_body_type);
CREATE INDEX IF NOT EXISTS idx_http_traffic_captured_at ON specus_http_traffic_exchange (captured_at);

CREATE TABLE IF NOT EXISTS specus_tcp_traffic_frame (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id TEXT NOT NULL,
  client_id INTEGER NOT NULL,
  client_name TEXT NOT NULL,
  listen_port INTEGER NOT NULL,
  resource_id INTEGER,
  resource_name TEXT,
  channel_id TEXT NOT NULL,
  frame_direction TEXT NOT NULL,
  remote_address TEXT,
  source_address TEXT,
  source_port INTEGER,
  destination_address TEXT,
  destination_port INTEGER,
  stream_offset INTEGER NOT NULL,
  stream_end_offset INTEGER NOT NULL,
  frame_index INTEGER NOT NULL,
  payload_bytes INTEGER NOT NULL,
  payload_data BLOB NOT NULL,
  payload_preview_hex TEXT,
  payload_preview_text TEXT,
  truncated INTEGER NOT NULL,
  frame_time TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_tcp_traffic_tenant ON specus_tcp_traffic_frame (tenant_id);
CREATE INDEX IF NOT EXISTS idx_tcp_traffic_client ON specus_tcp_traffic_frame (client_id);
CREATE INDEX IF NOT EXISTS idx_tcp_traffic_listen_port ON specus_tcp_traffic_frame (listen_port);
CREATE INDEX IF NOT EXISTS idx_tcp_traffic_channel ON specus_tcp_traffic_frame (channel_id);
CREATE INDEX IF NOT EXISTS idx_tcp_traffic_stream ON specus_tcp_traffic_frame (tenant_id, channel_id, frame_direction, stream_offset);
CREATE INDEX IF NOT EXISTS idx_tcp_traffic_frame_time ON specus_tcp_traffic_frame (frame_time);

CREATE TABLE IF NOT EXISTS peer_mesh_device (
  id INTEGER PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  owner_username TEXT NOT NULL,
  client_id INTEGER NOT NULL,
  client_name TEXT NOT NULL,
  virtual_ip TEXT NOT NULL,
  cidr TEXT NOT NULL,
  public_key TEXT,
  nat_type TEXT,
  nat_mapping_behavior TEXT,
  nat_filtering_behavior TEXT,
  nat_behavior_discovery TEXT,
  last_endpoint TEXT,
  virtual_device_mode TEXT,
  virtual_device_name TEXT,
  virtual_device_status TEXT,
  virtual_device_error TEXT,
  virtual_device_updated_at TEXT,
  enabled INTEGER NOT NULL DEFAULT 0,
  last_seen_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (tenant_id, client_id),
  UNIQUE (tenant_id, virtual_ip)
);

CREATE INDEX IF NOT EXISTS idx_peer_mesh_device_owner ON peer_mesh_device (tenant_id, owner_username);
CREATE INDEX IF NOT EXISTS idx_peer_mesh_device_client_name ON peer_mesh_device (client_name);

CREATE TABLE IF NOT EXISTS peer_mesh_acl (
  id INTEGER PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  owner_username TEXT NOT NULL,
  source_client_id INTEGER NOT NULL,
  source_client_name TEXT NOT NULL,
  target_client_id INTEGER NOT NULL,
  target_client_name TEXT NOT NULL,
  allowed INTEGER NOT NULL DEFAULT 1,
  direction TEXT NOT NULL DEFAULT 'OUTBOUND',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (tenant_id, source_client_id, target_client_id)
);

CREATE INDEX IF NOT EXISTS idx_peer_mesh_acl_source ON peer_mesh_acl (tenant_id, source_client_id);
CREATE INDEX IF NOT EXISTS idx_peer_mesh_acl_target ON peer_mesh_acl (tenant_id, target_client_id);

CREATE TABLE IF NOT EXISTS peer_mesh_session (
  id INTEGER PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  source_client_id INTEGER NOT NULL,
  source_client_name TEXT NOT NULL,
  target_client_id INTEGER NOT NULL,
  target_client_name TEXT NOT NULL,
  path_type TEXT NOT NULL,
  status TEXT NOT NULL,
  token_hash TEXT,
  started_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  closed_at TEXT,
  rtt_millis INTEGER,
  local_endpoint TEXT,
  remote_endpoint TEXT,
  direct_bytes INTEGER NOT NULL DEFAULT 0,
  relay_bytes INTEGER NOT NULL DEFAULT 0,
  last_traffic_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_peer_mesh_session_tenant ON peer_mesh_session (tenant_id);
CREATE INDEX IF NOT EXISTS idx_peer_mesh_session_source ON peer_mesh_session (tenant_id, source_client_id);
CREATE INDEX IF NOT EXISTS idx_peer_mesh_session_target ON peer_mesh_session (tenant_id, target_client_id);
CREATE INDEX IF NOT EXISTS idx_peer_mesh_session_status ON peer_mesh_session (status);

CREATE TABLE IF NOT EXISTS specus_connection_stat (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id TEXT NOT NULL DEFAULT 'default',
  client_id INTEGER,
  client_name TEXT NOT NULL,
  stat_month TEXT NOT NULL,
  total_count INTEGER NOT NULL,
  success_count INTEGER NOT NULL,
  failure_count INTEGER NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (tenant_id, client_name, stat_month)
);

CREATE INDEX IF NOT EXISTS idx_stat_tenant ON specus_connection_stat (tenant_id);
CREATE INDEX IF NOT EXISTS idx_stat_client_name ON specus_connection_stat (client_name);

-- Public transfer rooms (Batch 5, aligned with the Java management model).
CREATE TABLE IF NOT EXISTS public_transfer_room (
  id INTEGER PRIMARY KEY,
  room_name TEXT NOT NULL,
  owner_token_hash TEXT NOT NULL,
  created_by_peer_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (room_name, owner_token_hash)
);

CREATE INDEX IF NOT EXISTS idx_public_transfer_room_name ON public_transfer_room (room_name);

CREATE TABLE IF NOT EXISTS public_transfer_room_access (
  id INTEGER PRIMARY KEY,
  room_id INTEGER NOT NULL,
  token_hash TEXT NOT NULL,
  role TEXT NOT NULL,
  label TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT,
  revoked_at TEXT,
  UNIQUE (token_hash)
);

CREATE INDEX IF NOT EXISTS idx_public_transfer_access_room ON public_transfer_room_access (room_id);

CREATE TABLE IF NOT EXISTS public_transfer_room_pairing_code (
  id INTEGER PRIMARY KEY,
  room_id INTEGER NOT NULL,
  code_hash TEXT NOT NULL,
  role TEXT NOT NULL,
  label TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  max_uses INTEGER NOT NULL,
  used_count INTEGER NOT NULL,
  revoked_at TEXT,
  UNIQUE (code_hash)
);

CREATE INDEX IF NOT EXISTS idx_public_transfer_pairing_room ON public_transfer_room_pairing_code (room_id);

CREATE TABLE IF NOT EXISTS public_transfer_diagram_version (
  id INTEGER PRIMARY KEY,
  room_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  author_peer_id TEXT NOT NULL,
  snapshot_data BLOB NOT NULL,
  size_bytes INTEGER NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_public_transfer_version_room ON public_transfer_diagram_version (room_id);
CREATE INDEX IF NOT EXISTS idx_public_transfer_version_created ON public_transfer_diagram_version (created_at);

CREATE TABLE IF NOT EXISTS user_diagram_document (
  id INTEGER PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  owner_username TEXT NOT NULL,
  name TEXT NOT NULL,
  snapshot_data BLOB NOT NULL,
  size_bytes INTEGER NOT NULL,
  revision INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_user_diagram_owner ON user_diagram_document (tenant_id, owner_username);
CREATE INDEX IF NOT EXISTS idx_user_diagram_updated ON user_diagram_document (updated_at);
