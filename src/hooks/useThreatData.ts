import { useState, useEffect, useCallback } from 'react';
import { supabase } from '../lib/supabase';
import type { NetworkEvent, ThreatAlert, DetectionModel, DashboardStats, DataProfile } from '../types';

const SUPABASE_URL = import.meta.env.VITE_SUPABASE_URL;
const SUPABASE_ANON_KEY = import.meta.env.VITE_SUPABASE_ANON_KEY;

export function useThreatData() {
  const [events, setEvents] = useState<NetworkEvent[]>([]);
  const [alerts, setAlerts] = useState<ThreatAlert[]>([]);
  const [models, setModels] = useState<DetectionModel[]>([]);
  const [dataProfile, setDataProfile] = useState<DataProfile | null>(null);
  const [stats, setStats] = useState<DashboardStats>({
    totalEvents: 0,
    threatsDetected: 0,
    activeAlerts: 0,
    threatRate: 0,
    criticalAlerts: 0,
    resolvedAlerts: 0,
  });
  const [loading, setLoading] = useState(true);
  const [simulating, setSimulating] = useState(false);

  const fetchEvents = useCallback(async () => {
    const { data } = await supabase
      .from('network_events')
      .select('*')
      .order('created_at', { ascending: false })
      .limit(500);
    if (data) setEvents(data as NetworkEvent[]);
  }, []);

  const fetchAlerts = useCallback(async () => {
    const { data } = await supabase
      .from('threat_alerts')
      .select('*')
      .order('created_at', { ascending: false })
      .limit(200);
    if (data) setAlerts(data as ThreatAlert[]);
  }, []);

  const fetchModels = useCallback(async () => {
    const { data } = await supabase
      .from('detection_models')
      .select('*')
      .eq('is_active', true);
    if (data) setModels(data as DetectionModel[]);
  }, []);

  const computeStats = useCallback(() => {
    const totalEvents = events.length;
    const threatsDetected = events.filter((e) => e.is_threat).length;
    const activeAlerts = alerts.filter((a) => !a.resolved).length;
    const criticalAlerts = alerts.filter((a) => a.severity === 'critical' && !a.resolved).length;
    const resolvedAlerts = alerts.filter((a) => a.resolved).length;
    const threatRate = totalEvents > 0 ? threatsDetected / totalEvents : 0;
    setStats({ totalEvents, threatsDetected, activeAlerts, threatRate, criticalAlerts, resolvedAlerts });
  }, [events, alerts]);

  const simulateAndStore = useCallback(async (count: number = 50) => {
    setSimulating(true);
    try {
      await fetch(
        `${SUPABASE_URL}/functions/v1/threat-detection/simulate?count=${count}`,
        {
          headers: {
            Authorization: `Bearer ${SUPABASE_ANON_KEY}`,
            'Content-Type': 'application/json',
          },
        }
      );
      await fetchEvents();
      await fetchAlerts();
    } catch (err) {
      console.error('Simulation error:', err);
    } finally {
      setSimulating(false);
    }
  }, [fetchEvents, fetchAlerts]);

  useEffect(() => {
    (async () => {
      setLoading(true);
      await Promise.all([fetchEvents(), fetchAlerts(), fetchModels()]);
      setLoading(false);
    })();
  }, [fetchEvents, fetchAlerts, fetchModels]);

  useEffect(() => {
    computeStats();
  }, [computeStats]);

  return {
    events,
    alerts,
    models,
    stats,
    loading,
    simulating,
    simulateAndStore,
    fetchEvents,
    fetchAlerts,
    dataProfile,
    setDataProfile,
  };
}
