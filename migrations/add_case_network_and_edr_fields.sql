-- Add new columns to case table for network configuration and EDR reports
-- Migration: add_case_network_and_edr_fields.sql
-- Date: 2025-12-21

BEGIN;

-- Add OpenSearch index name (case-level indexing)
ALTER TABLE "case" ADD COLUMN IF NOT EXISTS opensearch_index VARCHAR(100);

-- Add router IPs (comma-separated)
ALTER TABLE "case" ADD COLUMN IF NOT EXISTS router_ips TEXT;

-- Add VPN IPs/subnets/ranges (comma-separated)
ALTER TABLE "case" ADD COLUMN IF NOT EXISTS vpn_ips TEXT;

-- Add EDR reports (multiple reports separated by *** NEW REPORT ***)
ALTER TABLE "case" ADD COLUMN IF NOT EXISTS edr_reports TEXT;

-- Grant permissions to casescope user
GRANT ALL PRIVILEGES ON TABLE "case" TO casescope;

COMMIT;

-- Notes:
-- opensearch_index: Store OpenSearch index name (e.g., 'case_123')
-- router_ips: Comma-separated list of router IPs (e.g., '192.168.1.1, 10.0.0.1')
-- vpn_ips: Comma-separated VPN IPs, can include:
--   - Single IPs: 192.168.1.100
--   - Subnets: 192.168.1.0/24
--   - Ranges: 192.168.1.50-192.168.1.60
-- edr_reports: Text field for EDR reports, multiple reports separated by *** NEW REPORT ***
