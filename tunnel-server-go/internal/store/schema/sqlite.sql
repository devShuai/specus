CREATE TABLE IF NOT EXISTS tunnel_client_account (
  id INTEGER PRIMARY KEY,
  client_name TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  enabled INTEGER NOT NULL,
  connection_rate_limit_per_minute INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tunnel_connection_record (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
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

CREATE INDEX IF NOT EXISTS idx_tunnel_connection_client_time ON tunnel_connection_record (client_id, connected_at);
CREATE INDEX IF NOT EXISTS idx_tunnel_connection_connected_at ON tunnel_connection_record (connected_at);

CREATE TABLE IF NOT EXISTS tunnel_mapping (
  id INTEGER PRIMARY KEY,
  client_id INTEGER NOT NULL,
  client_name TEXT NOT NULL,
  listen_port INTEGER NOT NULL UNIQUE,
  target_address TEXT NOT NULL,
  target_port INTEGER NOT NULL,
  enabled INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_tunnel_mapping_client_id ON tunnel_mapping (client_id);

CREATE TABLE IF NOT EXISTS http_route_mapping (
  id INTEGER PRIMARY KEY,
  client_id INTEGER NOT NULL,
  client_name TEXT NOT NULL,
  route TEXT NOT NULL,
  target_base_url TEXT NOT NULL,
  enabled INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (client_id, route)
);

CREATE INDEX IF NOT EXISTS idx_http_route_client_id ON http_route_mapping (client_id);

CREATE TABLE IF NOT EXISTS tunnel_traffic_usage (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  client_id INTEGER NOT NULL,
  client_name TEXT NOT NULL,
  usage_date TEXT NOT NULL,
  upload_bytes INTEGER NOT NULL,
  download_bytes INTEGER NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (client_id, usage_date)
);

CREATE INDEX IF NOT EXISTS idx_traffic_client_id ON tunnel_traffic_usage (client_id);

CREATE TABLE IF NOT EXISTS tunnel_connection_stat (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  client_id INTEGER,
  client_name TEXT NOT NULL,
  stat_month TEXT NOT NULL,
  total_count INTEGER NOT NULL,
  success_count INTEGER NOT NULL,
  failure_count INTEGER NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (client_name, stat_month)
);

CREATE INDEX IF NOT EXISTS idx_stat_client_name ON tunnel_connection_stat (client_name);
