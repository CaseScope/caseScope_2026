-- Add exclude_fields column to noise_filter_rules table
-- This allows specifying fields that should NOT be checked for pattern matches
-- Critical for EDR/RMM tools where agent URLs should be ignored

ALTER TABLE noise_filter_rules 
ADD COLUMN exclude_fields VARCHAR(500) DEFAULT NULL
COMMENT 'Comma-separated list of field names to exclude from pattern matching (e.g., agent.url,url,subdomain)';

-- Update existing EDR/RMM rules to exclude agent URL fields
UPDATE noise_filter_rules 
SET exclude_fields = 'agent.url,agent.id,url,subdomain,agent.type,agent.version'
WHERE name LIKE '%Huntress%' 
   OR name LIKE '%ConnectWise%' 
   OR name LIKE '%Datto%'
   OR name LIKE '%Kaseya%'
   OR name LIKE '%N-able%'
   OR name LIKE '%SolarWinds%'
   OR name LIKE '%Atera%'
   OR name LIKE '%NinjaOne%'
   OR name LIKE '%ManageEngine%';

-- Update existing EDR rules to exclude agent fields
UPDATE noise_filter_rules 
SET exclude_fields = 'agent.url,agent.id,url,subdomain,agent.type,agent.version'
WHERE name LIKE '%CrowdStrike%' 
   OR name LIKE '%SentinelOne%' 
   OR name LIKE '%Carbon Black%'
   OR name LIKE '%Defender%'
   OR name LIKE '%Cortex%'
   OR name LIKE '%Sophos%'
   OR name LIKE '%Trend Micro%'
   OR name LIKE '%McAfee%'
   OR name LIKE '%Symantec%'
   OR name LIKE '%ESET%'
   OR name LIKE '%Bitdefender%'
   OR name LIKE '%Malwarebytes%'
   OR name LIKE '%Webroot%';

