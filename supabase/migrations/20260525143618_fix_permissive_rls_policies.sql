/*
  # Fix Permissive RLS INSERT Policies

  1. Security Issue
    - INSERT policies on `network_events`, `threat_alerts`, and `system_metrics`
      used `WITH CHECK (true)`, allowing any authenticated user to insert
      arbitrary data. This bypasses row-level security entirely.
    - Public SELECT policies on all tables used `USING (true)`, which is
      acceptable for read-only dashboard display but should be reviewed.

  2. Changes
    - DROP the permissive INSERT policies:
      - "Authenticated users can insert network events" on network_events
      - "Authenticated users can insert threat alerts" on threat_alerts
      - "Authenticated users can insert system metrics" on system_metrics
    - No replacement INSERT policies are added. All data insertion now
      goes through the edge function (which runs with service_role key
      and bypasses RLS), so no direct client-side INSERT access is needed.

  3. Impact
    - Frontend code can still SELECT data freely for dashboard display.
    - Data insertion is only possible via the edge function, which has
      proper validation and threat detection logic before persisting.
    - Authenticated users can no longer directly insert arbitrary rows
      into these tables.
*/

-- Drop permissive INSERT policies
DROP POLICY IF EXISTS "Authenticated users can insert network events" ON network_events;
DROP POLICY IF EXISTS "Authenticated users can insert threat alerts" ON threat_alerts;
DROP POLICY IF EXISTS "Authenticated users can insert system metrics" ON system_metrics;
