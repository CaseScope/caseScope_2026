# Network Hunting

> **Note:** CaseScope network hunting is built from PCAP or PCAPNG captures processed by Zeek and indexed into ClickHouse. The page reviews indexed Zeek logs for the active case.

## Overview

The **Hunt Network** page is the case-level review surface for PCAP-derived network evidence. It loads `/case/hunting/network` and presents indexed Zeek logs from the ClickHouse `network_logs` table.

Use this page when the investigation question involves:

- Host-to-host connections, ports, protocols, services, byte counts, packet counts, or connection state
- DNS lookups, response codes, answers, and repeated name resolution
- HTTP requests, hosts, URIs, status codes, user agents, and MIME types
- TLS handshakes, SNI values, certificate subjects and issuers, validation status, and JA3 or JA3S fingerprints
- Files observed in network traffic, including filenames, MIME types, file sizes, hashes, and extraction paths
- Searching across all indexed Zeek logs for an IP address, domain, URI, hash, UID, service, or other raw Zeek value

Hunt Network is separate from Hunt Artifacts because PCAP-derived logs are stored in the dedicated ClickHouse `network_logs` table instead of the normalized `events` table.

## Data Flow

Network hunting starts with a PCAP file uploaded or rebuilt through the PCAP workflow.

1. A PCAP or PCAPNG file is tracked in PostgreSQL as a `pcap_files` record with filename, original filename, hash, hostname, upload source, archive/extraction metadata, status, Zeek output path, generated log count, indexed log count, and timestamps.
2. Celery runs Zeek from `/opt/zeek/bin/zeek` with `-r <pcap>` and `-C local` to ignore checksum errors and load the local Zeek policy.
3. Zeek writes `.log` files under the case storage path for that PCAP processing run.
4. CaseScope indexes supported Zeek log files into ClickHouse `network_logs`, storing normalized common fields, log-specific fields, the original Zeek row as `raw_json`, and a flattened `search_blob`.
5. Hunt Network reads indexed logs through `/api/network/hunting/<case_uuid>/...` endpoints.

The combined task `tasks.process_and_index_pcap` runs Zeek first and then indexes the generated logs. The Hunt Network page can also queue indexing for processed PCAPs that have Zeek output but no indexed rows.

## Page Layout

The page has four main areas:

- **Unified Findings Pivot:** loads case findings from `/api/findings/list/<case_uuid>` and shows the first few findings with confidence scores as quick context.
- **PCAP Source selector:** filters the hunting table to one indexed PCAP or all PCAPs. Each option shows filename, optional hostname, and indexing state.
- **Index All action:** queues indexing for processed PCAP files that have not been indexed yet. Viewer users cannot run indexing.
- **Network tabs:** show dedicated Zeek views for Connections, DNS, HTTP, SSL/TLS, Files, and Search All.

If a case has no completed PCAP records available to the page, Hunt Network shows a no-data state and links back to PCAP Files.

## API Endpoints

The page is rendered by `case_hunting_network` and populated by these network APIs:

- `/api/network/hunting/<case_uuid>/stats` returns total indexed rows, counts by log type, earliest and latest Zeek timestamps, and unique source and destination IP counts.
- `/api/network/hunting/<case_uuid>/pcap-stats` returns indexed log counts grouped by PCAP, source host, and log type.
- `/api/network/hunting/<case_uuid>/pcaps` returns completed, non-archive PCAP records with indexing state.
- `/api/network/hunting/<case_uuid>/logs` returns paginated rows for one log type with optional filters.
- `/api/network/hunting/<case_uuid>/search` searches all indexed log types through the flattened `search_blob`.
- `/api/network/hunting/<pcap_id>/index` queues indexing for one processed PCAP.
- `/api/network/hunting/<case_uuid>/index-all` queues indexing for all processed PCAPs in the case that have not yet been indexed.

The log list API defaults to `log_type=conn`, page `1`, and `50` rows per page. Requests are capped at `500` rows per page.

## Filters And Search

Filters are applied server-side against ClickHouse.

- **PCAP Source** limits results to one `pcap_id`.
- **Search** matches the `search_blob`, which is built from the original Zeek field names and values for each row.
- **Source IP** and **Dest IP** are available on the Connections tab and prefix-match `src_ip` and `dst_ip`.
- **Pagination** is supported for each tab and for Search All.
- **Sorting** is supported by the API for `timestamp`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `duration`, `orig_bytes`, and `resp_bytes`. The current UI uses the default timestamp ordering.

Search All requires a non-empty search term. It returns common fields across all matching log types: log type, timestamp, UID, source IP and port, destination IP and port, source host, PCAP ID, and raw Zeek JSON.

## Dedicated Hunt Network Tabs

### Connections

Source log: `conn.log`

Stored log type: `conn`

The Connections tab is the broadest network conversation view. It shows connection-level metadata extracted from Zeek connection records.

Displayed fields include:

- Timestamp
- Source IP and source port
- Destination IP and destination port
- Protocol
- Zeek service
- Duration
- Connection state
- Originator and responder byte counts

Additional stored fields include Zeek UID, missed bytes, originator packet count, responder packet count, raw JSON, PCAP ID, and source host.

Use Connections to answer questions such as:

- Which hosts communicated with a suspicious IP?
- Which ports and services were observed?
- Did the connection complete, fail, reset, or only show an initial SYN?
- How much data moved in each direction?
- Which PCAP and source host produced the evidence?

Connection rows can pivot to Hunt Artifacts by searching the destination IP in the main hunting page.

### DNS

Source log: `dns.log`

Stored log type: `dns`

The DNS tab focuses on name resolution activity observed in the capture.

Displayed fields include:

- Timestamp
- Source IP
- Destination IP
- Query
- Query type name
- Response code name
- Answers

Additional stored fields include source and destination ports, protocol, numeric query type, numeric response code, TTLs, rejected flag, Zeek UID, raw JSON, PCAP ID, and source host.

Use DNS to answer questions such as:

- Which domains were queried by a host?
- Which queries returned `NXDOMAIN`, refused, or other unusual responses?
- Which domains resolved to a suspicious IP?
- Were TXT, MX, AAAA, or other non-A record lookups present?

DNS answers and TTL values are stored as arrays when Zeek provides them.

### HTTP

Source log: `http.log`

Stored log type: `http`

The HTTP tab reviews unencrypted HTTP request and response metadata.

Displayed fields include:

- Timestamp
- Source IP
- Destination IP
- HTTP method
- Host header
- URI
- Status code
- User agent

Additional stored fields include referrer, request body length, response body length, status message, response MIME type, Zeek UID, raw JSON, PCAP ID, and source host.

Use HTTP to answer questions such as:

- Which hosts requested a suspicious domain, URI, or path?
- Which user agents were used?
- Which requests returned errors or redirects?
- Was a payload or file transfer associated with an HTTP request?

The tab truncates long URI and user-agent values in the table, but the detail modal retains the raw Zeek fields.

### SSL/TLS

Source log: `ssl.log`

Stored log type: `ssl`

The SSL/TLS tab reviews TLS handshake metadata and certificate context.

Displayed fields include:

- Timestamp
- Source IP
- Destination IP
- Server name indication
- TLS version
- Cipher
- JA3 fingerprint
- Certificate validation status

Additional stored fields include certificate subject, certificate issuer, JA3S fingerprint, Zeek UID, raw JSON, PCAP ID, and source host.

Use SSL/TLS to answer questions such as:

- Which SNI values were contacted by an endpoint?
- Which JA3 or JA3S fingerprints are present?
- Were self-signed, expired, or otherwise invalid certificates observed?
- Which certificate subjects or issuers were associated with traffic?

Certificate subject and issuer values are truncated in the table for readability and are available in full through the detail modal.

### Files

Source log: `files.log`

Stored log type: `files`

The Files tab reviews files Zeek observed in network traffic.

Displayed fields include:

- Timestamp
- Source IP
- Destination IP
- Filename
- MIME type
- File size
- MD5 hash
- SHA256 hash

Additional stored fields include file UID, source protocol or analyzer source, analyzers, SHA1 hash, extracted path, raw JSON, PCAP ID, and source host.

Use Files to answer questions such as:

- Which files moved across the network?
- Which hashes were observed and can be promoted to IOCs?
- Which MIME types appeared in transfer metadata?
- Which traffic source produced a file record?

File size is populated from `seen_bytes` or `total_bytes` when Zeek provides either field.

### Search All

Search All queries every indexed row in `network_logs` for the active case, regardless of whether the log type has a dedicated UI tab.

It is useful for:

- IP addresses
- Domains and hostnames
- URLs or URI fragments
- Zeek UIDs and file UIDs
- Hashes
- JA3 or JA3S values
- User agents
- Certificate strings
- Service names
- Account, protocol, or application strings from raw Zeek fields

Search All returns common network context and opens the same raw-detail modal as the dedicated tabs.

## Indexed Log Types Without Dedicated Tabs

The indexing task supports these Zeek log types in addition to the dedicated tabs:

- `x509`
- `smtp`
- `ssh`
- `dhcp`
- `ftp`
- `ntp`
- `rdp`
- `smb`
- `dce_rpc`
- `kerberos`
- `ntlm`

These rows are stored with their original Zeek fields in `raw_json` and searchable text in `search_blob`. They do not currently have dedicated Hunt Network tabs or specialized display columns. Search All is the primary UI path for finding them.

The model also defines a display column set for `ntp`, so the API can return a focused NTP table if `log_type=ntp` is requested directly, but the current template does not expose an NTP tab.

## Detail Modal And Pivots

Each visible row has a detail action that opens the raw Zeek row. The modal parses `raw_json` when available and displays non-empty fields.

Rows with a destination IP also show a pivot action that opens Hunt Artifacts with that IP address as the search term. This is useful when the same indicator may appear in firewall logs, endpoint telemetry, Windows events, browser artifacts, or other parsed events.

## Storage Model

The ClickHouse `network_logs` table stores:

- Case ID, log type, timestamp, PCAP ID, source host, and Zeek UID
- Common network fields such as source/destination IP, source/destination port, protocol, service, duration, bytes, packets, and connection state
- DNS fields such as query, query type, response code, answers, TTLs, and rejected status
- HTTP fields such as method, host, URI, referrer, user agent, body lengths, status, and MIME type
- SSL/TLS fields such as version, cipher, SNI, subject, issuer, validation status, JA3, and JA3S
- File fields such as file UID, source, analyzers, MIME type, filename, size, hashes, and extraction path
- `raw_json` for the full Zeek row
- `search_blob` for full-text style searching
- `indexed_at` for indexing time

The table is partitioned by case ID and log type, ordered by case ID, log type, PCAP ID, and timestamp, and uses bloom/ngram indexes for search acceleration.

## Indexing States

The PCAP selector describes each processed PCAP with one of these states:

- **Indexed:** `logs_indexed` is greater than zero.
- **Index failed:** the PCAP has an error message beginning with `Indexing error:`.
- **Pending index:** Zeek generated logs, but no rows are indexed yet.
- **No indexed data:** no indexed rows are available for the PCAP.

Indexing errors are stored on the `pcap_files` record without changing a successful Zeek processing result into a Zeek failure.

## Time Behavior

Zeek timestamps are parsed from Unix epoch values with microsecond precision and stored in ClickHouse as `DateTime64(6)`. The API serializes timestamp values as ISO strings. The current network table formatter renders those values with JavaScript ISO formatting.

Time range filters exist in the `/logs` API as `time_start` and `time_end`, but the current page template does not expose time range controls.

## Analyst Workflow

A typical network-hunting workflow is:

1. Confirm the PCAP source selector shows indexed data, or use **Index All** for processed PCAPs that are pending indexing.
2. Start with Connections to identify relevant IP pairs, ports, services, connection states, and byte counts.
3. Move to DNS, HTTP, SSL/TLS, and Files to enrich the network conversation with names, URLs, certificates, fingerprints, and transferred file metadata.
4. Use Search All for indicators that may appear in any Zeek log type, including raw-only log families.
5. Open row details to inspect the complete Zeek fields behind a table row.
6. Pivot destination IPs to Hunt Artifacts when endpoint, firewall, browser, or event telemetry may contain related evidence.
7. Promote strong indicators such as domains, IPs, URLs, hashes, JA3 values, and certificate strings into the IOC workflow when appropriate.

## Limitations

Network Hunting is a Zeek-indexed PCAP review surface. It does not replace packet-level analysis.

- Only supported Zeek `.log` files are indexed into `network_logs`.
- Dedicated UI tabs currently exist for `conn`, `dns`, `http`, `ssl`, and `files`.
- Additional supported Zeek log types are searchable but do not have specialized table views in the current template.
- Search depends on fields present in Zeek output and stored in `search_blob`.
- Raw packet payloads are not shown in Hunt Network.
- Encrypted traffic is represented by handshake, certificate, SNI, JA3, and flow metadata, not decrypted content.
- Reprocessing, rebuilding, or deleting PCAPs can remove and recreate indexed ClickHouse rows for the affected PCAP or case.
