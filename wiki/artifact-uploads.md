# Artifact Uploads

CaseScope has several upload paths because different artifact types need different handling. Some uploads are parsed and indexed for hunting. Others are retained as evidence for download, archive, and chain-of-custody purposes but are not parsed.

Use the upload path that matches the investigation goal:

- **Indexed case files** for logs and forensic artifacts that should be parsed into searchable records.
- **Evidence uploads** for files that should be retained with the case but not indexed.
- **PCAP uploads** for packet captures that should be processed with Zeek.
- **Memory uploads** for memory images that should be processed with Volatility3.

## Indexed Case Files

Use the standard case upload page for artifacts that should become searchable in CaseScope.

Typical examples include:

- Windows Event Logs
- browser artifacts
- registry artifacts
- prefetch
- LNK files
- MFT data
- SRUM data
- Windows ETL trace files
- JSON, NDJSON, and CSV logs
- firewall logs
- supported vendor logs
- CyLR or KAPE triage ZIPs

### How To Upload

From the case upload page:

1. Open the target case.
2. Upload files through the browser dropzone or place files in the case SFTP upload folder.
3. Scan or refresh the upload queue.
4. Review each queued file before ingest.
5. Set the correct upload type when auto-detect is not enough.
6. Confirm or correct the hostname.
7. Start ingest.

### Upload Type

Each queued file has a type selection. The type helps CaseScope choose the correct parser behavior.

Use **Auto-detect / Other** when the file name and content should be enough for CaseScope to resolve the parser.

Choose a specific type when you know the source, such as:

- CyLR / Triage ZIP
- KAPE Triage ZIP
- IIS logs
- SonicWall logs
- Huntress reports or logs
- SentinelOne or Sophos exports
- generic JSON, NDJSON, or CSV logs
- any other parser-specific option shown in the upload queue

Correct type selection matters most when files share common extensions such as `.json`, `.csv`, `.log`, or archives. Parser hints from the selected type are passed into the background parser task.

Windows ETL files (`.etl` and `.etlgz`) are indexed with a `windows_etl` parent metadata record. CaseScope preserves source path, source file, host, file size, hashes, and parser status, then attempts best-effort `dissect.etl` decoding. Meaningful decoded records are emitted as `windows_etl_event` child rows; unsupported or low-value provider payloads remain metadata-only. Raw binary ETL samples are not added to `search_blob`. Existing hunting filters that reference the legacy `etl_trace` type still match these records.

### Hostname

Set the hostname to the system that produced the artifact.

CaseScope may derive a hostname automatically from supported naming patterns, including some KAPE-style filenames. Analysts should still review the queue and fix the hostname before ingest if needed.

Use consistent hostnames across uploads. For example, if a host is known as `WIN-DFIR-01`, use that same value for EVTX, registry, browser, and triage artifacts from that system. Consistent names make correlation, known-system discovery, hunting filters, and summaries more useful.

### Time Zone

The upload form does not require a time zone per file. CaseScope uses the case time zone during parsing where parsers need case-local time interpretation. Other parsers may preserve UTC or source timestamps depending on the artifact type.

Set the case time zone correctly before ingesting time-sensitive artifacts.

### How Indexed Ingestion Works

Indexed ingest follows this general flow:

1. Uploaded files are staged under the case upload area.
2. CaseScope creates `CaseFile` records in PostgreSQL.
3. Original files are retained under the case originals path.
4. Working copies are placed in staging.
5. Celery queues `parse_file` tasks for files that should be parsed.
6. The parser registry resolves the correct parser from file metadata, type hints, and content.
7. Parsed event data is written to ClickHouse when the artifact produces searchable events.
8. Completion tasks run deduplication, known-user discovery, known-system discovery, and ingest summaries as applicable.

If CaseScope cannot find a parser, the file is retained and marked with a no-parser ingestion state. It is not indexed for hunting, but it remains associated with the case.

### Archives And Triage ZIPs

ZIP uploads are handled specially. CaseScope retains the archive, extracts supported members into staging, and processes extracted artifacts where parser support exists.

For KAPE or CyLR triage ZIPs, select the matching upload type when available. This gives CaseScope better parser hints and improves artifact classification.

Archive parent files may be retained for chain-of-custody and marked as archived or no-parser while extracted child artifacts are parsed separately.

## Evidence Uploads

Use evidence uploads for files that must be kept with the case but should not be parsed or indexed.

Typical examples include:

- signed statements
- screenshots
- PDFs or office documents
- legal or administrative documents
- unrelated supporting material
- files preserved for chain of custody
- artifacts that should be retained but not searched in hunting views

### How To Upload

From the evidence area:

1. Open the target case.
2. Upload the file through the evidence upload form, or place files in the case evidence bulk folder.
3. Add or update the description when useful.
4. Confirm the file appears in the evidence list.

Evidence uploads use the active case context. File type is generally derived from the file extension.

### How Evidence Storage Works

Evidence files are stored under the case evidence path and tracked with `EvidenceFile` records.

These files are intentionally not parsed. They are retained so analysts can download, review, preserve, and archive them with the case. They do not create ClickHouse hunting records and do not enter the normal parser pipeline.

Use this path when the goal is retention rather than indexing.

## PCAP Uploads

Use the PCAP upload workflow for network captures that should be processed into Zeek logs and indexed for network hunting.

Typical examples include:

- `.pcap`
- `.pcapng`
- packet captures exported from sensors or EDR tools

### How To Upload

From the PCAP workflow:

1. Open the target case.
2. Upload the PCAP through the PCAP upload flow or place it in the case PCAP folder.
3. Scan or refresh the PCAP queue.
4. Confirm or correct the hostname.
5. Ingest the PCAP into the case.
6. Start processing for one PCAP or process all queued PCAPs.

### Hostname

For PCAPs, hostname should identify the source system, sensor, network segment, or collection point that produced the capture.

Examples:

- `sensor-dmz-01`
- `firewall-edge`
- `WIN-DFIR-01`
- `corp-vpn-capture`

CaseScope may try to detect a hostname from the filename, but analysts should correct it when the filename does not clearly identify the capture source.

### How PCAP Ingestion Works

PCAP ingestion creates a `PcapFile` record, retains the original capture, and prepares a staging copy for processing.

Processing runs through Celery:

1. CaseScope queues PCAP processing.
2. Zeek runs against the capture.
3. Zeek output is written under the case PCAP storage area.
4. Supported Zeek log types are parsed.
5. Network records are indexed into ClickHouse with the case and hostname context.
6. The PCAP becomes available for network review and hunting.

The original capture remains retained. Temporary staging copies may be removed after processing.

### When To Use PCAP Upload Instead Of File Upload

Use the PCAP workflow for packet captures. Do not upload PCAPs through the generic indexed file upload path unless specifically directed by a maintainer. The PCAP workflow knows how to run Zeek, track PCAP processing status, and index network logs correctly.

## Memory Uploads

Use the memory workflow for memory images that should be processed with Volatility3.

Typical examples include:

- raw memory images
- memory dumps from triage tools
- supported memory acquisition formats

### How To Upload

From the memory workflow:

1. Open the target case.
2. Upload the memory image through the memory upload flow or place it in the case memory upload folder.
3. Submit the memory job.
4. Provide the required metadata:
   - source file
   - hostname
   - operating system type
   - memory type
   - selected Volatility plugins, if you do not want the default set
5. Start processing.

### Hostname

Use the hostname of the system from which the memory image was acquired. Use the same hostname used for that system's event logs and other artifacts when possible.

### Operating System And Memory Type

Set the operating system type and memory type to match the acquired image. These values help CaseScope track the job and select appropriate processing behavior.

Selected plugins control which Volatility3 plugins run. Use defaults for general triage and select focused plugins when you only need specific memory artifacts.

### How Memory Ingestion Works

Memory processing is a separate workflow from normal file parsing:

1. The uploaded image is moved or copied into retained originals for the case.
2. CaseScope creates a `MemoryJob`.
3. Celery queues memory processing.
4. A working copy is prepared in memory staging.
5. Volatility3 runs the selected plugins.
6. Plugin JSON output is written under case storage.
7. Parsed memory results are ingested into PostgreSQL memory tables.
8. The UI can show memory results and pivots from those tables.

The original memory image is retained. Volatility output and parsed results are stored separately so memory jobs can be reviewed or rebuilt.

### Re-Ingesting Memory Results

Some memory routes allow re-ingesting existing Volatility JSON output without rerunning all plugins. Use this when output exists but parsed tables need to be rebuilt or refreshed.

## Non-Indexed Files

Not every file uploaded to CaseScope becomes searchable.

Files can be retained without indexing when:

- they are uploaded through the evidence workflow
- no parser exists for the file type
- an archive parent is retained while extracted child files are parsed
- nested archive content is preserved but not directly parsed
- a file is intentionally kept for chain-of-custody only

Non-indexed retained files are still important. They preserve context, source material, and case history. They simply do not create ClickHouse event rows or hunting records.

Use the evidence workflow for files you know should be retained only. Use indexed case upload when the file should be parsed if supported.

## Choosing The Right Upload Path

Use this quick guide:

- Use **Indexed Case Files** for supported logs and forensic artifacts that should appear in hunting.
- Use **Evidence Uploads** for retained documents, screenshots, legal material, or files that should not be parsed.
- Use **PCAP Uploads** for packet captures that should run through Zeek.
- Use **Memory Uploads** for memory images that should run through Volatility3.

If unsure, ask whether the file should become searchable forensic data. If yes, start with indexed case upload or the dedicated PCAP/memory workflow. If no, use evidence upload.

## Practical Upload Advice

- Set the case time zone before ingesting time-sensitive artifacts.
- Review upload type before ingesting generic extensions such as `.json`, `.csv`, `.log`, and `.zip`.
- Correct hostnames before ingest so correlation works consistently.
- Use dedicated PCAP and memory workflows for those artifact types.
- Use evidence upload for files that should be preserved but not parsed.
- Keep originals and archives backed up according to the case retention plan.
- Check job progress and service logs when large uploads or background jobs appear stalled.

## Troubleshooting

If an uploaded file does not appear in hunting:

1. Confirm it was uploaded through an indexed path, not evidence upload.
2. Confirm the file type has parser support.
3. Confirm the upload type was selected correctly.
4. Confirm the hostname and case were correct.
5. Check Celery worker status.
6. Check parsing status on the case file.
7. Check service logs for parser or ClickHouse errors.

If a PCAP does not show network results, confirm Zeek is installed at `/opt/zeek/bin/zeek`, the PCAP was processed, and ClickHouse network log tables exist.

If memory results do not appear, confirm the memory job completed, selected plugins ran successfully, and the output was ingested into the memory tables.
