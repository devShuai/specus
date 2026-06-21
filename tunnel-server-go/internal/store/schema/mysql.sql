CREATE TABLE IF NOT EXISTS tunnel_client_account (
  id BIGINT NOT NULL PRIMARY KEY,
  client_name VARCHAR(120) NOT NULL,
  password_hash VARCHAR(64) NOT NULL,
  enabled TINYINT(1) NOT NULL,
  connection_rate_limit_per_minute INT NOT NULL,
  created_at VARCHAR(40) NOT NULL,
  updated_at VARCHAR(40) NOT NULL,
  UNIQUE KEY uq_client_account_name (client_name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS tunnel_connection_record (
  id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  client_id BIGINT,
  client_name VARCHAR(120) NOT NULL,
  channel_id VARCHAR(160),
  remote_address VARCHAR(255),
  connected_at VARCHAR(40) NOT NULL,
  disconnected_at VARCHAR(40),
  success TINYINT(1) NOT NULL,
  failure_reason VARCHAR(255),
  disconnect_reason VARCHAR(40),
  KEY idx_tunnel_connection_client_time (client_id, connected_at),
  KEY idx_tunnel_connection_connected_at (connected_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS tunnel_mapping (
  id BIGINT NOT NULL PRIMARY KEY,
  client_id BIGINT NOT NULL,
  client_name VARCHAR(120) NOT NULL,
  listen_port INT NOT NULL,
  target_address VARCHAR(255) NOT NULL,
  target_port INT NOT NULL,
  enabled TINYINT(1) NOT NULL,
  created_at VARCHAR(40) NOT NULL,
  updated_at VARCHAR(40) NOT NULL,
  UNIQUE KEY uq_tunnel_mapping_listen_port (listen_port),
  KEY idx_tunnel_mapping_client_id (client_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS http_route_mapping (
  id BIGINT NOT NULL PRIMARY KEY,
  client_id BIGINT NOT NULL,
  client_name VARCHAR(120) NOT NULL,
  route VARCHAR(60) NOT NULL,
  target_base_url VARCHAR(512) NOT NULL,
  enabled TINYINT(1) NOT NULL,
  created_at VARCHAR(40) NOT NULL,
  updated_at VARCHAR(40) NOT NULL,
  UNIQUE KEY uq_http_route_client_route (client_id, route),
  KEY idx_http_route_client_id (client_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS tunnel_traffic_usage (
  id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  client_id BIGINT NOT NULL,
  client_name VARCHAR(120) NOT NULL,
  usage_date VARCHAR(10) NOT NULL,
  upload_bytes BIGINT NOT NULL,
  download_bytes BIGINT NOT NULL,
  updated_at VARCHAR(40) NOT NULL,
  UNIQUE KEY uq_traffic_client_date (client_id, usage_date),
  KEY idx_traffic_client_id (client_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS tunnel_connection_stat (
  id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  client_id BIGINT,
  client_name VARCHAR(120) NOT NULL,
  stat_month VARCHAR(7) NOT NULL,
  total_count BIGINT NOT NULL,
  success_count BIGINT NOT NULL,
  failure_count BIGINT NOT NULL,
  updated_at VARCHAR(40) NOT NULL,
  UNIQUE KEY uq_stat_client_month (client_name, stat_month),
  KEY idx_stat_client_name (client_name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
