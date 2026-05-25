export interface NetworkEvent {
  id: string;
  source_ip: string;
  destination_ip: string;
  source_port: number;
  destination_port: number;
  protocol: string;
  packet_size: number;
  duration: number;
  bytes_sent: number;
  bytes_received: number;
  failed_logins: number;
  service: string;
  state: string;
  is_threat: boolean;
  threat_type: string;
  anomaly_score: number;
  created_at: string;
}

export interface ThreatAlert {
  id: string;
  event_id: string | null;
  severity: 'critical' | 'high' | 'medium' | 'low';
  threat_category: string;
  description: string;
  source_ip: string;
  confidence: number;
  resolved: boolean;
  created_at: string;
}

export interface DetectionModel {
  id: string;
  model_type: string;
  version: string;
  accuracy: number;
  precision: number;
  recall: number;
  f1_score: number;
  is_active: boolean;
  trained_at: string;
}

export interface SystemMetric {
  id: string;
  metric_type: string;
  value: number;
  recorded_at: string;
}

export interface ThreatDetectionResult {
  is_threat: boolean;
  threat_type: string;
  anomaly_score: number;
  severity: string;
  confidence: number;
  description: string;
}

export interface DashboardStats {
  totalEvents: number;
  threatsDetected: number;
  activeAlerts: number;
  threatRate: number;
  criticalAlerts: number;
  resolvedAlerts: number;
}

export interface ModelMetrics {
  model_type: string;
  accuracy: number;
  precision: number;
  recall: number;
  f1_score: number;
  confusion_matrix: number[][];
  class_names: string[];
  training_loss: number[];
  val_loss: number[];
}

export interface DataProfile {
  rowCount: number;
  colCount: number;
  columns: ColumnProfile[];
  missingValues: number;
  threatDistribution: Record<string, number>;
  protocolDistribution: Record<string, number>;
}

export interface ColumnProfile {
  name: string;
  type: string;
  missing: number;
  unique: number;
  sample: string;
}

export interface TimeSeriesPoint {
  time: string;
  normal: number;
  threats: number;
  total: number;
}

export interface AttackTrendPoint {
  date: string;
  ddos: number;
  intrusion: number;
  port_scan: number;
  brute_force: number;
  data_exfiltration: number;
  anomaly: number;
}
