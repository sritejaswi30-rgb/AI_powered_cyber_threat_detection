/*
  # Cyber Threat Detection System - Database Schema

  1. New Tables
    - `network_events`
      - `id` (uuid, primary key) - Unique event identifier
      - `source_ip` (text) - Source IP address
      - `destination_ip` (text) - Destination IP address
      - `source_port` (integer) - Source port number
      - `destination_port` (integer) - Destination port number
      - `protocol` (text) - Network protocol (TCP, UDP, ICMP, etc.)
      - `packet_size` (integer) - Size of packet in bytes
      - `duration` (float8) - Connection duration in seconds
      - `bytes_sent` (bigint) - Total bytes sent
      - `bytes_received` (bigint) - Total bytes received
      - `failed_logins` (integer) - Number of failed login attempts
      - `service` (text) - Network service type
      - `state` (text) - Connection state
      - `is_threat` (boolean) - Whether event is classified as threat
      - `threat_type` (text) - Type of threat if detected
      - `anomaly_score` (float8) - Anomaly score from autoencoder (0-1)
      - `created_at` (timestamptz) - Event timestamp

    - `threat_alerts`
      - `id` (uuid, primary key) - Unique alert identifier
      - `event_id` (uuid, foreign key) - Reference to network event
      - `severity` (text) - Alert severity (critical, high, medium, low)
      - `threat_category` (text) - Category (ddos, intrusion, malware, port_scan, brute_force, data_exfiltration)
      - `description` (text) - Human-readable alert description
      - `source_ip` (text) - Source IP involved
      - `confidence` (float8) - Detection confidence (0-1)
      - `resolved` (boolean) - Whether alert has been resolved
      - `created_at` (timestamptz) - Alert timestamp

    - `detection_models`
      - `id` (uuid, primary key) - Model identifier
      - `model_type` (text) - Type of model (random_forest, autoencoder, ensemble)
      - `version` (text) - Model version string
      - `accuracy` (float8) - Model accuracy metric
      - `precision` (float8) - Model precision metric
      - `recall` (float8) - Model recall metric
      - `f1_score` (float8) - F1 score
      - `is_active` (boolean) - Whether model is currently active
      - `trained_at` (timestamptz) - When model was trained

    - `system_metrics`
      - `id` (uuid, primary key) - Metric identifier
      - `metric_type` (text) - Type of metric (events_per_sec, threats_detected, cpu_usage, memory_usage)
      - `value` (float8) - Metric value
      - `recorded_at` (timestamptz) - When metric was recorded

  2. Security
    - Enable RLS on all tables
    - Public read access for dashboard display
    - Authenticated users can insert events and alerts
    - Only service role can manage models and resolve alerts

  3. Indexes
    - Index on network_events.created_at for time-based queries
    - Index on network_events.source_ip for IP-based lookups
    - Index on network_events.is_threat for filtering threats
    - Index on threat_alerts.severity for severity filtering
    - Index on threat_alerts.created_at for recent alerts
*/

-- Network Events Table
CREATE TABLE IF NOT EXISTS network_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  source_ip text NOT NULL DEFAULT '',
  destination_ip text NOT NULL DEFAULT '',
  source_port integer DEFAULT 0,
  destination_port integer DEFAULT 0,
  protocol text NOT NULL DEFAULT 'TCP',
  packet_size integer DEFAULT 0,
  duration float8 DEFAULT 0.0,
  bytes_sent bigint DEFAULT 0,
  bytes_received bigint DEFAULT 0,
  failed_logins integer DEFAULT 0,
  service text DEFAULT '',
  state text DEFAULT '',
  is_threat boolean DEFAULT false,
  threat_type text DEFAULT '',
  anomaly_score float8 DEFAULT 0.0,
  created_at timestamptz DEFAULT now()
);

-- Threat Alerts Table
CREATE TABLE IF NOT EXISTS threat_alerts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  event_id uuid REFERENCES network_events(id) ON DELETE SET NULL,
  severity text NOT NULL DEFAULT 'low',
  threat_category text NOT NULL DEFAULT '',
  description text NOT NULL DEFAULT '',
  source_ip text NOT NULL DEFAULT '',
  confidence float8 DEFAULT 0.0,
  resolved boolean DEFAULT false,
  created_at timestamptz DEFAULT now()
);

-- Detection Models Table
CREATE TABLE IF NOT EXISTS detection_models (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  model_type text NOT NULL DEFAULT '',
  version text NOT NULL DEFAULT '1.0.0',
  accuracy float8 DEFAULT 0.0,
  precision float8 DEFAULT 0.0,
  recall float8 DEFAULT 0.0,
  f1_score float8 DEFAULT 0.0,
  is_active boolean DEFAULT false,
  trained_at timestamptz DEFAULT now()
);

-- System Metrics Table
CREATE TABLE IF NOT EXISTS system_metrics (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  metric_type text NOT NULL DEFAULT '',
  value float8 DEFAULT 0.0,
  recorded_at timestamptz DEFAULT now()
);

-- Enable RLS on all tables
ALTER TABLE network_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE threat_alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE detection_models ENABLE ROW LEVEL SECURITY;
ALTER TABLE system_metrics ENABLE ROW LEVEL SECURITY;

-- RLS Policies for network_events
CREATE POLICY "Public can read network events"
  ON network_events FOR SELECT
  TO public
  USING (true);

CREATE POLICY "Authenticated users can insert network events"
  ON network_events FOR INSERT
  TO authenticated
  WITH CHECK (true);

-- RLS Policies for threat_alerts
CREATE POLICY "Public can read threat alerts"
  ON threat_alerts FOR SELECT
  TO public
  USING (true);

CREATE POLICY "Authenticated users can insert threat alerts"
  ON threat_alerts FOR INSERT
  TO authenticated
  WITH CHECK (true);

-- RLS Policies for detection_models
CREATE POLICY "Public can read detection models"
  ON detection_models FOR SELECT
  TO public
  USING (true);

-- RLS Policies for system_metrics
CREATE POLICY "Public can read system metrics"
  ON system_metrics FOR SELECT
  TO public
  USING (true);

CREATE POLICY "Authenticated users can insert system metrics"
  ON system_metrics FOR INSERT
  TO authenticated
  WITH CHECK (true);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_network_events_created_at ON network_events (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_network_events_source_ip ON network_events (source_ip);
CREATE INDEX IF NOT EXISTS idx_network_events_is_threat ON network_events (is_threat);
CREATE INDEX IF NOT EXISTS idx_threat_alerts_severity ON threat_alerts (severity);
CREATE INDEX IF NOT EXISTS idx_threat_alerts_created_at ON threat_alerts (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_system_metrics_recorded_at ON system_metrics (recorded_at DESC);
