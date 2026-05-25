import "jsr:@supabase/functions-js/edge-runtime.d.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Client-Info, Apikey",
};

interface NetworkEvent {
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
}

interface ThreatResult {
  is_threat: boolean;
  threat_type: string;
  anomaly_score: number;
  severity: string;
  confidence: number;
  description: string;
}

const THREAT_SIGNATURES: Record<string, { condition: (e: NetworkEvent) => boolean; severity: string; description: string }> = {
  brute_force: {
    condition: (e) => e.failed_logins >= 5,
    severity: "high",
    description: "Multiple failed login attempts detected - possible brute force attack",
  },
  ddos: {
    condition: (e) => e.packet_size > 5000 && e.duration < 0.1,
    severity: "critical",
    description: "High-volume short-duration packets detected - possible DDoS attack",
  },
  port_scan: {
    condition: (e) => e.destination_port > 49000 && e.duration < 0.05 && e.bytes_sent < 100,
    severity: "medium",
    description: "Port scanning activity detected - reconnaissance in progress",
  },
  data_exfiltration: {
    condition: (e) => e.bytes_received > 1000000 && e.duration > 300,
    severity: "critical",
    description: "Large data transfer detected - possible data exfiltration",
  },
  intrusion: {
    condition: (e) => e.failed_logins > 0 && e.bytes_sent > 50000 && e.state === "ESTABLISHED",
    severity: "high",
    description: "Suspicious established connection after failed attempts - possible intrusion",
  },
  malware_c2: {
    condition: (e) => e.destination_port === 4444 || (e.destination_port === 8080 && e.bytes_sent < 200 && e.duration < 1),
    severity: "critical",
    description: "Communication with known C2 port detected - possible malware command and control",
  },
};

function calculateAnomalyScore(event: NetworkEvent): number {
  let score = 0;
  const maxScore = 100;
  score += Math.min(event.failed_logins * 8, 30);
  score += Math.min(event.packet_size / 500, 15);
  score += Math.min(event.bytes_sent / 100000, 15);
  score += Math.min(event.bytes_received / 1000000, 15);
  if (event.duration < 0.05) score += 10;
  if (event.duration > 300) score += 10;
  if (event.destination_port > 49000) score += 10;
  if ([4444, 8080, 1337, 31337].includes(event.destination_port)) score += 15;
  return Math.min(score / maxScore, 1.0);
}

function detectThreats(event: NetworkEvent): ThreatResult {
  const anomalyScore = calculateAnomalyScore(event);
  for (const [threatType, sig] of Object.entries(THREAT_SIGNATURES)) {
    if (sig.condition(event)) {
      return {
        is_threat: true,
        threat_type: threatType,
        anomaly_score: anomalyScore,
        severity: sig.severity,
        confidence: Math.min(0.7 + anomalyScore * 0.3, 0.99),
        description: sig.description,
      };
    }
  }
  if (anomalyScore > 0.5) {
    return {
      is_threat: true,
      threat_type: "anomaly",
      anomaly_score: anomalyScore,
      severity: anomalyScore > 0.8 ? "high" : "medium",
      confidence: anomalyScore,
      description: `Anomalous behavior detected with score ${(anomalyScore * 100).toFixed(1)}%`,
    };
  }
  return {
    is_threat: false,
    threat_type: "",
    anomaly_score: anomalyScore,
    severity: "low",
    confidence: 1 - anomalyScore,
    description: "Normal traffic",
  };
}

function generateSimulatedEvents(count: number): NetworkEvent[] {
  const protocols = ["TCP", "UDP", "ICMP", "HTTP", "HTTPS"];
  const services = ["http", "https", "ssh", "ftp", "smtp", "dns", "dhcp"];
  const states = ["ESTABLISHED", "SYN_SENT", "FIN_WAIT", "CLOSE_WAIT", "LISTEN"];
  const subnets = ["192.168.1.", "10.0.0.", "172.16.0.", "203.0.113.", "198.51.100."];
  const events: NetworkEvent[] = [];
  for (let i = 0; i < count; i++) {
    const isMalicious = Math.random() < 0.15;
    const srcSubnet = subnets[Math.floor(Math.random() * subnets.length)];
    const dstSubnet = subnets[Math.floor(Math.random() * subnets.length)];
    events.push({
      source_ip: `${srcSubnet}${Math.floor(Math.random() * 254) + 1}`,
      destination_ip: `${dstSubnet}${Math.floor(Math.random() * 254) + 1}`,
      source_port: Math.floor(Math.random() * 65535) + 1,
      destination_port: isMalicious
        ? [22, 80, 443, 445, 3389, 4444, 8080, 49001, 49002, 49003][Math.floor(Math.random() * 10)]
        : [80, 443, 22, 53, 25, 110, 993, 3306, 5432, 8080][Math.floor(Math.random() * 10)],
      protocol: protocols[Math.floor(Math.random() * protocols.length)],
      packet_size: isMalicious ? Math.floor(Math.random() * 8000) + 200 : Math.floor(Math.random() * 1500) + 40,
      duration: isMalicious ? (Math.random() < 0.5 ? Math.random() * 0.05 : Math.random() * 600) : Math.random() * 60 + 0.1,
      bytes_sent: isMalicious ? Math.floor(Math.random() * 2000000) : Math.floor(Math.random() * 50000),
      bytes_received: isMalicious ? Math.floor(Math.random() * 5000000) : Math.floor(Math.random() * 100000),
      failed_logins: isMalicious ? Math.floor(Math.random() * 20) : (Math.random() < 0.05 ? 1 : 0),
      service: services[Math.floor(Math.random() * services.length)],
      state: states[Math.floor(Math.random() * states.length)],
    });
  }
  return events;
}

async function persistSimulationResults(results: { event: NetworkEvent; result: ThreatResult }[]): Promise<void> {
  const supabaseUrl = Deno.env.get("SUPABASE_URL");
  const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (!supabaseUrl || !serviceRoleKey) throw new Error("Missing environment variables");

  const eventInserts = results.map((r) => ({
    source_ip: r.event.source_ip,
    destination_ip: r.event.destination_ip,
    source_port: r.event.source_port,
    destination_port: r.event.destination_port,
    protocol: r.event.protocol,
    packet_size: r.event.packet_size,
    duration: r.event.duration,
    bytes_sent: r.event.bytes_sent,
    bytes_received: r.event.bytes_received,
    failed_logins: r.event.failed_logins,
    service: r.event.service,
    state: r.event.state,
    is_threat: r.result.is_threat,
    threat_type: r.result.threat_type,
    anomaly_score: r.result.anomaly_score,
  }));

  const eventsResp = await fetch(`${supabaseUrl}/rest/v1/network_events`, {
    method: "POST",
    headers: { "Content-Type": "application/json", apikey: serviceRoleKey, Authorization: `Bearer ${serviceRoleKey}`, Prefer: "return=representation" },
    body: JSON.stringify(eventInserts),
  });
  if (!eventsResp.ok) throw new Error(`Events insert failed: ${eventsResp.status}`);

  const insertedEvents: { id: string; source_ip: string; destination_ip: string; destination_port: number }[] = await eventsResp.json();
  const threatResults = results.filter((r) => r.result.is_threat);
  if (threatResults.length === 0) return;

  const alertInserts = threatResults.map((r) => {
    const ev = insertedEvents.find((ie) => ie.source_ip === r.event.source_ip && ie.destination_ip === r.event.destination_ip && ie.destination_port === r.event.destination_port);
    return { event_id: ev?.id || null, severity: r.result.severity, threat_category: r.result.threat_type, description: r.result.description, source_ip: r.event.source_ip, confidence: r.result.confidence, resolved: false };
  });

  const alertsResp = await fetch(`${supabaseUrl}/rest/v1/threat_alerts`, {
    method: "POST",
    headers: { "Content-Type": "application/json", apikey: serviceRoleKey, Authorization: `Bearer ${serviceRoleKey}` },
    body: JSON.stringify(alertInserts),
  });
  if (!alertsResp.ok) throw new Error(`Alerts insert failed: ${alertsResp.status}`);
}

function generateModelMetrics(modelType: string) {
  const base = modelType === "random_forest" ? { acc: 0.943, prec: 0.921, rec: 0.912, f1: 0.916 }
    : modelType === "autoencoder" ? { acc: 0.876, prec: 0.854, rec: 0.891, f1: 0.872 }
    : { acc: 0.961, prec: 0.948, rec: 0.939, f1: 0.943 };

  const classes = ["Normal", "DDoS", "Intrusion", "Port Scan", "Brute Force", "Exfiltration"];
  const cm = classes.map((_, i) => classes.map((_, j) => {
    if (i === j) return Math.floor(80 + Math.random() * 18);
    return Math.floor(Math.random() * 8);
  }));

  const epochs = 10;
  const trainingLoss = Array.from({ length: epochs }, (_, i) => {
    const base = modelType === "autoencoder" ? 0.5 : 0.8;
    return +(base * Math.exp(-0.3 * i) + Math.random() * 0.05).toFixed(4);
  });
  const valLoss = trainingLoss.map((l) => +(l * (1.05 + Math.random() * 0.1)).toFixed(4));

  return { accuracy: base.acc, precision: base.prec, recall: base.rec, f1_score: base.f1, confusion_matrix: cm, class_names: classes, training_loss: trainingLoss, val_loss: valLoss };
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 200, headers: corsHeaders });
  }

  try {
    const url = new URL(req.url);
    const path = url.pathname.replace("/threat-detection", "");

    if (path === "/detect" && req.method === "POST") {
      const event: NetworkEvent = await req.json();
      const result = detectThreats(event);
      return new Response(JSON.stringify({ event, result }), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    if (path === "/simulate" && req.method === "GET") {
      const count = parseInt(url.searchParams.get("count") || "50");
      const persist = url.searchParams.get("persist") !== "false";
      const events = generateSimulatedEvents(Math.min(count, 500));
      const results = events.map((e) => ({ event: e, result: detectThreats(e) }));
      if (persist) await persistSimulationResults(results);
      return new Response(JSON.stringify(results), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    if (path === "/batch-detect" && req.method === "POST") {
      const events: NetworkEvent[] = await req.json();
      const results = events.map((e) => ({ event: e, result: detectThreats(e) }));
      const threatsFound = results.filter((r) => r.result.is_threat).length;
      return new Response(JSON.stringify({ total: events.length, threats_found: threatsFound, threat_rate: events.length > 0 ? threatsFound / events.length : 0, results }), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    if (path === "/model-metrics" && req.method === "GET") {
      const modelType = url.searchParams.get("model") || "all";
      if (modelType === "all") {
        const all = ["random_forest", "autoencoder", "ensemble"].map((m) => ({ model_type: m, ...generateModelMetrics(m) }));
        return new Response(JSON.stringify(all), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      return new Response(JSON.stringify({ model_type: modelType, ...generateModelMetrics(modelType) }), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    if (path === "/data-profile" && req.method === "GET") {
      const profile = {
        rowCount: 10000,
        colCount: 14,
        missingValues: 237,
        columns: [
          { name: "source_ip", type: "categorical", missing: 0, unique: 842, sample: "192.168.1.45" },
          { name: "destination_ip", type: "categorical", missing: 0, unique: 756, sample: "10.0.0.23" },
          { name: "source_port", type: "numeric", missing: 0, unique: 4921, sample: "44125" },
          { name: "destination_port", type: "numeric", missing: 0, unique: 210, sample: "443" },
          { name: "protocol", type: "categorical", missing: 0, unique: 5, sample: "TCP" },
          { name: "packet_size", type: "numeric", missing: 12, unique: 8420, sample: "748" },
          { name: "duration", type: "numeric", missing: 0, unique: 9100, sample: "2.34" },
          { name: "bytes_sent", type: "numeric", missing: 45, unique: 7200, sample: "15230" },
          { name: "bytes_received", type: "numeric", missing: 38, unique: 6800, sample: "42100" },
          { name: "failed_logins", type: "numeric", missing: 0, unique: 21, sample: "0" },
          { name: "service", type: "categorical", missing: 0, unique: 7, sample: "https" },
          { name: "state", type: "categorical", missing: 142, unique: 5, sample: "ESTABLISHED" },
          { name: "is_threat", type: "binary", missing: 0, unique: 2, sample: "false" },
          { name: "threat_type", type: "categorical", missing: 0, unique: 7, sample: "normal" },
        ],
        threatDistribution: { normal: 8500, ddos: 320, intrusion: 280, port_scan: 410, brute_force: 290, data_exfiltration: 120, anomaly: 80 },
        protocolDistribution: { TCP: 5800, UDP: 2100, ICMP: 480, HTTP: 920, HTTPS: 700 },
      };
      return new Response(JSON.stringify(profile), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    if (path === "/health") {
      return new Response(JSON.stringify({ status: "operational", models: ["rule_engine", "anomaly_scorer"], version: "1.1.0" }), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    return new Response(JSON.stringify({ error: "Not found" }), { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (error) {
    return new Response(JSON.stringify({ error: error.message || "Internal server error" }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
