CREATE TABLE IF NOT EXISTS tunnel_client_account (
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

CREATE INDEX IF NOT EXISTS idx_tunnel_client_tenant ON tunnel_client_account (tenant_id);
CREATE INDEX IF NOT EXISTS idx_tunnel_client_owner ON tunnel_client_account (tenant_id, owner_username);

CREATE TABLE IF NOT EXISTS tunnel_client_credential (
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

CREATE INDEX IF NOT EXISTS idx_client_credential_tenant ON tunnel_client_credential (tenant_id);
CREATE INDEX IF NOT EXISTS idx_client_credential_owner ON tunnel_client_credential (tenant_id, owner_username);

CREATE TABLE IF NOT EXISTS tunnel_client_identity (
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

CREATE INDEX IF NOT EXISTS idx_client_identity_tenant ON tunnel_client_identity (tenant_id);
CREATE INDEX IF NOT EXISTS idx_client_identity_client ON tunnel_client_identity (client_id);

CREATE TABLE IF NOT EXISTS tunnel_client_session (
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

CREATE INDEX IF NOT EXISTS idx_client_session_token ON tunnel_client_session (token_hash);
CREATE INDEX IF NOT EXISTS idx_client_session_credential_status ON tunnel_client_session (credential_id, status);
CREATE INDEX IF NOT EXISTS idx_client_session_machine_status ON tunnel_client_session (credential_id, machine_fingerprint, os_user, status);
CREATE INDEX IF NOT EXISTS idx_client_session_client_status ON tunnel_client_session (client_id, status);

CREATE TABLE IF NOT EXISTS tunnel_management_user (
  username TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL,
  enabled INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_management_user_tenant ON tunnel_management_user (tenant_id);
CREATE INDEX IF NOT EXISTS idx_management_user_role ON tunnel_management_user (role);

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

CREATE TABLE IF NOT EXISTS tunnel_connection_record (
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

CREATE INDEX IF NOT EXISTS idx_tunnel_connection_tenant ON tunnel_connection_record (tenant_id);
CREATE INDEX IF NOT EXISTS idx_tunnel_connection_client_time ON tunnel_connection_record (client_id, connected_at);
CREATE INDEX IF NOT EXISTS idx_tunnel_connection_connected_at ON tunnel_connection_record (connected_at);

CREATE TABLE IF NOT EXISTS tunnel_mapping (
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

CREATE INDEX IF NOT EXISTS idx_tunnel_mapping_client_id ON tunnel_mapping (client_id);

CREATE TABLE IF NOT EXISTS http_route_mapping (
  id INTEGER PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  client_id INTEGER NOT NULL,
  client_name TEXT NOT NULL,
  route TEXT NOT NULL,
  target_base_url TEXT NOT NULL,
  enabled INTEGER NOT NULL,
  detail_capture_enabled INTEGER NOT NULL DEFAULT 0,
  path_rewrite_enabled INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (client_id, route)
);

CREATE INDEX IF NOT EXISTS idx_http_route_client_id ON http_route_mapping (client_id);

CREATE TABLE IF NOT EXISTS tunnel_traffic_usage (
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

CREATE INDEX IF NOT EXISTS idx_tunnel_traffic_tenant ON tunnel_traffic_usage (tenant_id);
CREATE INDEX IF NOT EXISTS idx_traffic_client_id ON tunnel_traffic_usage (client_id);

CREATE TABLE IF NOT EXISTS tunnel_resource_traffic_usage (
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

CREATE INDEX IF NOT EXISTS idx_resource_traffic_tenant ON tunnel_resource_traffic_usage (tenant_id);
CREATE INDEX IF NOT EXISTS idx_resource_traffic_client ON tunnel_resource_traffic_usage (client_id);
CREATE INDEX IF NOT EXISTS idx_resource_traffic_type ON tunnel_resource_traffic_usage (resource_type);
CREATE INDEX IF NOT EXISTS idx_resource_traffic_date ON tunnel_resource_traffic_usage (usage_date);

CREATE TABLE IF NOT EXISTS tunnel_http_traffic_exchange (
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

CREATE INDEX IF NOT EXISTS idx_http_traffic_tenant ON tunnel_http_traffic_exchange (tenant_id);
CREATE INDEX IF NOT EXISTS idx_http_traffic_client ON tunnel_http_traffic_exchange (client_id);
CREATE INDEX IF NOT EXISTS idx_http_traffic_route ON tunnel_http_traffic_exchange (route);
CREATE INDEX IF NOT EXISTS idx_http_traffic_body_type ON tunnel_http_traffic_exchange (response_body_type);
CREATE INDEX IF NOT EXISTS idx_http_traffic_captured_at ON tunnel_http_traffic_exchange (captured_at);

CREATE TABLE IF NOT EXISTS tunnel_tcp_traffic_frame (
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

CREATE INDEX IF NOT EXISTS idx_tcp_traffic_tenant ON tunnel_tcp_traffic_frame (tenant_id);
CREATE INDEX IF NOT EXISTS idx_tcp_traffic_client ON tunnel_tcp_traffic_frame (client_id);
CREATE INDEX IF NOT EXISTS idx_tcp_traffic_listen_port ON tunnel_tcp_traffic_frame (listen_port);
CREATE INDEX IF NOT EXISTS idx_tcp_traffic_channel ON tunnel_tcp_traffic_frame (channel_id);
CREATE INDEX IF NOT EXISTS idx_tcp_traffic_stream ON tunnel_tcp_traffic_frame (tenant_id, channel_id, frame_direction, stream_offset);
CREATE INDEX IF NOT EXISTS idx_tcp_traffic_frame_time ON tunnel_tcp_traffic_frame (frame_time);

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

CREATE TABLE IF NOT EXISTS tunnel_connection_stat (
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

CREATE INDEX IF NOT EXISTS idx_stat_tenant ON tunnel_connection_stat (tenant_id);
CREATE INDEX IF NOT EXISTS idx_stat_client_name ON tunnel_connection_stat (client_name);
