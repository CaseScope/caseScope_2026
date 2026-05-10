"""Shared helpers for hunting query routes."""

import re
from datetime import datetime, timedelta

SEARCH_FIELD_MAP = {
    "eventid": ("event_id", "eq"),
    "event_id": ("event_id", "eq"),
    "id": ("event_id", "eq"),
    "channel": ("channel", "like"),
    "provider": ("provider", "like"),
    "level": ("level", "eq"),
    "recordid": ("record_id", "eq"),
    "host": ("source_host", "like"),
    "hostname": ("source_host", "like"),
    "source_host": ("source_host", "like"),
    "computer": ("source_host", "like"),
    "artifact": ("artifact_type", "eq"),
    "parser": ("artifact_type", "eq"),
    "type": ("artifact_type", "eq"),
    "user": ("username", "like"),
    "username": ("username", "like"),
    "domain": ("domain", "like"),
    "sid": ("sid", "like"),
    "logontype": ("logon_type", "eq"),
    "logon_type": ("logon_type", "eq"),
    "process": ("process_name", "like"),
    "process_name": ("process_name", "like"),
    "proc": ("process_name", "like"),
    "cmd": ("command_line", "like"),
    "commandline": ("command_line", "like"),
    "command_line": ("command_line", "like"),
    "parent": ("parent_process", "like"),
    "parent_process": ("parent_process", "like"),
    "pid": ("process_id", "eq"),
    "ppid": ("parent_pid", "eq"),
    "path": ("target_path", "like"),
    "file": ("target_path", "like"),
    "target_path": ("target_path", "like"),
    "filename": ("target_path", "like"),
    "md5": ("file_hash_md5", "eq"),
    "sha1": ("file_hash_sha1", "eq"),
    "sha256": ("file_hash_sha256", "eq"),
    "hash": ("file_hash_sha256", "like"),
    "ip": ("src_ip", "eq"),
    "srcip": ("src_ip", "eq"),
    "src_ip": ("src_ip", "eq"),
    "dstip": ("dst_ip", "eq"),
    "dst_ip": ("dst_ip", "eq"),
    "srcipraw": ("src_ip_raw", "blob"),
    "src_ip_raw": ("src_ip_raw", "blob"),
    "dstipraw": ("dst_ip_raw", "blob"),
    "dst_ip_raw": ("dst_ip_raw", "blob"),
    "srcnatip": ("src_nat_ip", "blob"),
    "src_nat_ip": ("src_nat_ip", "blob"),
    "dstnatip": ("dst_nat_ip", "blob"),
    "dst_nat_ip": ("dst_nat_ip", "blob"),
    "natip": ("src_nat_ip", "blob"),
    "nat_ip": ("src_nat_ip", "blob"),
    "port": ("dst_port", "eq"),
    "srcport": ("src_port", "eq"),
    "dstport": ("dst_port", "eq"),
    "regkey": ("reg_key", "like"),
    "reg_key": ("reg_key", "like"),
    "registry": ("reg_key", "like"),
    "regvalue": ("reg_value", "like"),
    "regdata": ("reg_data", "like"),
    "rule": ("rule_title", "like"),
    "rule_title": ("rule_title", "like"),
    "severity": ("rule_level", "eq"),
    "rule_level": ("rule_level", "eq"),
    "keylength": None,
    "authpackage": None,
    "authenticationpackagename": None,
    "logonprocess": None,
    "logonprocessname": None,
    "workstationname": None,
    "ipaddress": None,
    "ipport": None,
    "targetusername": None,
    "subjectusername": None,
    "targetdomainname": None,
    "targetusersid": None,
    "subjectusersid": None,
    "targetlogonid": None,
    "subjectlogonid": None,
    "status": None,
    "substatus": None,
    "failurereason": None,
    "elevatedtoken": None,
    "servicename": None,
    "servicefilename": None,
    "taskname": None,
    "objectname": None,
    "objecttype": None,
    "accessmask": None,
    "privilegelist": None,
    "newprocessname": None,
    "parentprocessname": None,
    "targetfilename": None,
    "hashes": None,
}

LEGACY_ARTIFACT_TYPE_ALIASES = {
    "etl_trace": ["windows_etl", "windows_etl_event"],
    "windows_etl": ["etl_trace"],
}


def build_hunting_type_filter(artifact_types_param: str, params: dict) -> str:
    """Build a parameterized artifact type filter."""
    if artifact_types_param == "__none__":
        return " AND 1=0"

    raw_types = [artifact_type.strip() for artifact_type in artifact_types_param.split(",") if artifact_type.strip()]
    expanded_types = []
    for artifact_type in raw_types:
        expanded_types.append(artifact_type)
        expanded_types.extend(LEGACY_ARTIFACT_TYPE_ALIASES.get(artifact_type, []))
    artifact_types = list(dict.fromkeys(expanded_types))
    if not artifact_types:
        return ""

    placeholders = []
    for index, artifact_type in enumerate(artifact_types):
        param_name = f"artifact_type_{index}"
        params[param_name] = artifact_type
        placeholders.append(f"{{{param_name}:String}}")

    return f" AND artifact_type IN ({', '.join(placeholders)})"


def _build_search_blob_field_condition(field_name: str, value: str, param_prefix: str, params: dict) -> str:
    """Build a search_blob key:value match condition."""
    param_name = f"{param_prefix}_blob"
    params[param_name] = f"%{field_name}:{value}%"
    return f"search_blob ilike {{{param_name}:String}}"


def _build_ip_field_search_condition(field_lower: str, column: str, value: str, param_prefix: str, params: dict) -> str:
    """Match IPv4 event columns and preserved searchable IP tokens."""
    if field_lower == "ip":
        direct_src = f"{param_prefix}_src"
        direct_dst = f"{param_prefix}_dst"
        params[direct_src] = value
        params[direct_dst] = value
        conditions = [
            f"toString(src_ip) = {{{direct_src}:String}}",
            f"toString(dst_ip) = {{{direct_dst}:String}}",
        ]
        for token_field in ("src_ip", "dst_ip", "src_nat_ip", "dst_nat_ip"):
            conditions.append(
                _build_search_blob_field_condition(
                    token_field,
                    value,
                    f"{param_prefix}_{token_field}",
                    params,
                )
            )
        return f"({' OR '.join(conditions)})"

    direct_param = f"{param_prefix}_fld"
    params[direct_param] = value
    token_field = "src_ip" if column == "src_ip" else "dst_ip"
    token_condition = _build_search_blob_field_condition(
        token_field,
        value,
        f"{param_prefix}_{token_field}",
        params,
    )
    return f"(toString({column}) = {{{direct_param}:String}} OR {token_condition})"


def _parse_event_field_value_condition(field: str, value: str, param_prefix: str, params: dict) -> str:
    """Parse a field:value pair into a ClickHouse condition."""
    field_lower = field.lower()

    if field_lower in ("natip", "nat_ip"):
        return (
            "("
            + _build_search_blob_field_condition("src_nat_ip", value, f"{param_prefix}_src_nat", params)
            + " OR "
            + _build_search_blob_field_condition("dst_nat_ip", value, f"{param_prefix}_dst_nat", params)
            + ")"
        )

    mapping = SEARCH_FIELD_MAP.get(field_lower)

    if mapping is None and field_lower in SEARCH_FIELD_MAP:
        return _build_search_blob_field_condition(field_lower, value, param_prefix, params)
    if mapping:
        column, match_type = mapping

        if match_type == "blob":
            return _build_search_blob_field_condition(column, value, param_prefix, params)

        if match_type == "eq":
            if field_lower == "ip" or column in ("src_ip", "dst_ip"):
                return _build_ip_field_search_condition(field_lower, column, value, param_prefix, params)

            param_name = f"{param_prefix}_fld"
            params[param_name] = value
            return f"{column} = {{{param_name}:String}}"

        param_name = f"{param_prefix}_fld"
        params[param_name] = f"%{value}%"
        return f"{column} ilike {{{param_name}:String}}"

    return _build_search_blob_field_condition(field_lower, value, param_prefix, params)


SIGMA_EVENT_CONDITION = (
    "((rule_title IS NOT NULL AND rule_title != '') "
    "OR (rule_level IS NOT NULL AND rule_level != ''))"
)


def _normalize_alert_filter_param(name: str, value: str) -> str:
    normalized = (value or "").strip().lower()
    if normalized in ("", "include"):
        return "include"
    if normalized == "exclude":
        return "exclude"
    raise ValueError(f"Invalid {name} filter: {value}")


def _build_sigma_alert_condition(severity_levels_param: str) -> str:
    """Build the SIGMA match condition, optionally narrowed by severity."""
    if not severity_levels_param:
        return SIGMA_EVENT_CONDITION

    if severity_levels_param == "__none__":
        return "0"

    levels_list = [level.strip().lower() for level in severity_levels_param.split(",") if level.strip()]
    if not levels_list:
        return SIGMA_EVENT_CONDITION

    normalized_buckets = set()
    for level in levels_list:
        if level in ("info", "informational"):
            normalized_buckets.add("info")
        elif level == "low":
            normalized_buckets.add("low")
        elif level in ("med", "medium"):
            normalized_buckets.add("medium")
        elif level in ("high", "crit", "critical"):
            normalized_buckets.add("high")

    if normalized_buckets == {"info", "low", "medium", "high"}:
        return SIGMA_EVENT_CONDITION

    safe_rule_levels = []
    if "info" in normalized_buckets:
        safe_rule_levels.extend(["informational", "info"])
    if "low" in normalized_buckets:
        safe_rule_levels.append("low")
    if "medium" in normalized_buckets:
        safe_rule_levels.extend(["medium", "med"])
    if "high" in normalized_buckets:
        safe_rule_levels.extend(["high", "critical", "crit"])

    if not safe_rule_levels:
        return "0"

    quoted_levels = "', '".join(sorted(set(safe_rule_levels)))
    return f"({SIGMA_EVENT_CONDITION} AND lower(rule_level) IN ('{quoted_levels}'))"


def _build_hunting_alert_type_filter(
    sigma_filter_param: str,
    ioc_filter_param: str,
    analyst_filter_param: str,
    other_filter_param: str,
    severity_levels_param: str,
    *,
    analyst_tagged_sql: str = "analyst_tagged",
    has_ioc_sql: str = "length(ioc_types) > 0",
) -> str:
    """Build an inclusive OR filter over the selected alert-type checkboxes."""
    selected_conditions = []

    sigma_mode = _normalize_alert_filter_param("sigma", sigma_filter_param)
    ioc_mode = _normalize_alert_filter_param("ioc", ioc_filter_param)
    analyst_mode = _normalize_alert_filter_param("analyst", analyst_filter_param)
    other_mode = _normalize_alert_filter_param("other", other_filter_param)

    if sigma_mode != "exclude":
        selected_conditions.append(_build_sigma_alert_condition(severity_levels_param))

    if ioc_mode != "exclude":
        selected_conditions.append(has_ioc_sql)

    if analyst_mode != "exclude":
        selected_conditions.append(f"{analyst_tagged_sql} = true")

    if other_mode != "exclude":
        selected_conditions.append(
            f"(NOT {SIGMA_EVENT_CONDITION} AND NOT ({has_ioc_sql}) AND {analyst_tagged_sql} = false)"
        )

    if not selected_conditions:
        return " AND 1=0"

    return f" AND ({' OR '.join(selected_conditions)})"


def build_hunting_time_filter(
    client,
    case_id: int,
    case_tz: str,
    time_range: str,
    time_start: str,
    time_end: str,
    params: dict,
) -> str:
    """Build a validated time filter for hunting queries."""
    normalized_range = (time_range or "").strip().lower()
    if not normalized_range or normalized_range == "none":
        return ""

    if normalized_range in ("1d", "3d", "7d", "30d"):
        max_ts_query = "SELECT max(COALESCE(timestamp_utc, timestamp)) FROM events WHERE case_id = {case_id:UInt32}"
        max_ts_result = client.query(max_ts_query, parameters={"case_id": case_id})
        max_timestamp = max_ts_result.result_rows[0][0] if max_ts_result.result_rows and max_ts_result.result_rows[0][0] else None
        if not max_timestamp:
            return ""

        days_map = {"1d": 1, "3d": 3, "7d": 7, "30d": 30}
        start_utc = max_timestamp - timedelta(days=days_map[normalized_range])
        params["time_start"] = start_utc.strftime("%Y-%m-%d %H:%M:%S")
        return " AND COALESCE(timestamp_utc, timestamp) >= {time_start:String}"

    if normalized_range != "custom":
        raise ValueError(f"Unsupported time range: {time_range}")

    if not time_start or not time_end:
        raise ValueError("Custom time range requires both time_start and time_end")

    from utils.timezone import to_utc

    start_local = datetime.strptime(time_start, "%Y-%m-%dT%H:%M")
    end_local = datetime.strptime(time_end, "%Y-%m-%dT%H:%M")
    if end_local < start_local:
        raise ValueError("Custom time range end must be after start")

    start_utc = to_utc(start_local, case_tz)
    end_utc = to_utc(end_local, case_tz)
    params["time_start"] = start_utc.strftime("%Y-%m-%d %H:%M:%S")
    params["time_end"] = end_utc.strftime("%Y-%m-%d %H:%M:%S")
    return (
        " AND COALESCE(timestamp_utc, timestamp) >= {time_start:String}"
        " AND COALESCE(timestamp_utc, timestamp) <= {time_end:String}"
    )


def build_hunting_search_clause(search: str, params: dict) -> str:
    """Build the shared search clause for live-grid and export queries."""
    if not search:
        return ""

    exclude_pattern = re.compile(r'-"([^"]+)"|-([^\s|()]+)')

    def parse_field_value(field, value, param_prefix):
        return _parse_event_field_value_condition(field, value, param_prefix, params)

    def parse_term(term, prefix):
        conditions = []

        if term.startswith("-"):
            excl_match = exclude_pattern.match(term)
            if excl_match:
                excl_term = excl_match.group(1) or excl_match.group(2)
                if excl_term:
                    excl_fv_match = re.match(r"^([a-zA-Z_][a-zA-Z0-9_]*):(.+)$", excl_term)
                    if excl_fv_match and "://" not in excl_term:
                        cond = parse_field_value(excl_fv_match.group(1), excl_fv_match.group(2), f"{prefix}_excl")
                        if cond:
                            return ([f"NOT ({cond})"], True)
                    else:
                        param_name = f"{prefix}_excl"
                        params[param_name] = f"%{excl_term}%"
                        return ([f"NOT search_blob ilike {{{param_name}:String}}"], True)
            return ([], False)

        field_value_match = re.match(r"^([a-zA-Z_][a-zA-Z0-9_]*):(.+)$", term)
        if field_value_match and "://" not in term:
            field = field_value_match.group(1)
            value = field_value_match.group(2)

            if "|" in value:
                or_parts = [part.strip() for part in value.split("|") if part.strip()]
                if or_parts:
                    or_conditions = []
                    for index, part in enumerate(or_parts):
                        part_fv_match = re.match(r"^([a-zA-Z_][a-zA-Z0-9_]*):(.+)$", part)
                        if part_fv_match and "://" not in part:
                            cond = parse_field_value(part_fv_match.group(1), part_fv_match.group(2), f"{prefix}_or{index}")
                        else:
                            cond = parse_field_value(field, part, f"{prefix}_or{index}")
                        if cond:
                            or_conditions.append(cond)
                    if or_conditions:
                        conditions.append(f"({' OR '.join(or_conditions)})")
            else:
                cond = parse_field_value(field, value, prefix)
                if cond:
                    conditions.append(cond)
            return (conditions, False)

        if "|" in term:
            or_parts = [part.strip() for part in term.split("|") if part.strip()]
            if or_parts:
                or_conditions = []
                for index, part in enumerate(or_parts):
                    or_param = f"{prefix}_or{index}"
                    fv_match = re.match(r"^([a-zA-Z_][a-zA-Z0-9_]*):(.+)$", part)
                    if fv_match and "://" not in part:
                        cond = parse_field_value(fv_match.group(1), fv_match.group(2), f"{prefix}_or{index}")
                        if cond:
                            or_conditions.append(cond)
                    elif part.isdigit():
                        params[or_param] = part
                        or_conditions.append(f"event_id = {{{or_param}:String}}")
                    else:
                        params[or_param] = f"%{part}%"
                        or_conditions.append(f"search_blob ilike {{{or_param}:String}}")
                if or_conditions:
                    conditions.append(f"({' OR '.join(or_conditions)})")
        elif term.isdigit():
            param_name = f"{prefix}_id"
            params[param_name] = term
            conditions.append(f"event_id = {{{param_name}:String}}")
        else:
            param_name = f"{prefix}_txt"
            params[param_name] = f"%{term}%"
            conditions.append(f"search_blob ilike {{{param_name}:String}}")

        return (conditions, False)

    def parse_group(group_str, prefix):
        positive_conditions = []
        exclusion_conditions = []
        token_pattern = re.compile(r'-"[^"]+"|-[^\s|()]+|"[^"]+"|[^\s()]+')
        tokens = token_pattern.findall(group_str)

        for index, token in enumerate(tokens):
            if token == "|":
                continue
            if token.startswith('"') and token.endswith('"'):
                token = token[1:-1]

            term_conditions, is_exclusion = parse_term(token, f"{prefix}_{index}")
            if is_exclusion:
                exclusion_conditions.extend(term_conditions)
            else:
                positive_conditions.extend(term_conditions)

        return (positive_conditions, exclusion_conditions)

    def build_group_sql(positive_conditions, exclusion_conditions):
        all_conditions = positive_conditions + exclusion_conditions
        if all_conditions:
            return f"({' AND '.join(all_conditions)})"
        return None

    paren_pattern = re.compile(r"\(([^)]+)\)")
    paren_groups = paren_pattern.findall(search)
    outside_content = paren_pattern.sub(" ", search).strip()

    global_positive = []
    global_exclusions = []
    if outside_content:
        outside_clean = re.sub(r"\s*\|\s*", " ", outside_content).strip()
        if outside_clean:
            global_positive, global_exclusions = parse_group(outside_clean, "global")

    search_conditions = []

    if paren_groups:
        has_group_or = bool(re.search(r"\)\s*\|\s*\(", search))
        has_mixed_or = bool(re.search(r"\)\s*\|(?!\s*\()", search)) or bool(re.search(r"(?<!\))\|\s*\(", search))

        group_sqls = []
        for index, group_content in enumerate(paren_groups):
            positive_conditions, exclusion_conditions = parse_group(group_content.strip(), f"g{index}")
            group_sql = build_group_sql(positive_conditions, exclusion_conditions)
            if group_sql:
                group_sqls.append(group_sql)

        if has_mixed_or:
            outside_or_terms = []
            if outside_content:
                outside_parts = [part.strip() for part in outside_content.split("|") if part.strip()]
                for index, part in enumerate(outside_parts):
                    if part.startswith("-"):
                        continue
                    positive_conditions, _ = parse_group(part, f"mixed_or_{index}")
                    outside_or_terms.extend(positive_conditions)

            all_or_parts = group_sqls + outside_or_terms
            if all_or_parts:
                search_conditions.append(f"({' OR '.join(all_or_parts)})")

            search_conditions.extend(global_exclusions)
        elif group_sqls:
            if has_group_or or len(group_sqls) > 1:
                search_conditions.append(f"({' OR '.join(group_sqls)})")
            else:
                search_conditions.append(group_sqls[0])

            search_conditions.extend(global_positive)
            search_conditions.extend(global_exclusions)
    else:
        positive_conditions, exclusion_conditions = parse_group(search, "simple")
        search_conditions.extend(positive_conditions)
        search_conditions.extend(exclusion_conditions)

    if not search_conditions:
        return ""

    return f" AND {' AND '.join(search_conditions)}"


def build_event_description(artifact_type, channel, provider, username, process_name, command_line, target_path, search_blob):
    """Build a human-readable description for an event."""
    parts = []

    if artifact_type in ("windows_etl", "etl_trace"):
        return "Windows ETL trace file metadata preserved."
    if artifact_type == "windows_etl_event":
        if provider:
            return f"ETL event from provider {provider}"
        if search_blob:
            blob_preview = search_blob[:150] + "..." if len(search_blob) > 150 else search_blob
            return blob_preview
        return "Decoded Windows ETL event"

    if artifact_type == "evtx":
        if channel:
            parts.append(f"[{channel}]")
        if provider:
            parts.append(provider)

    if username and username != "-":
        parts.append(f"User: {username}")

    if process_name and process_name != "-":
        parts.append(f"Process: {process_name}")

    if command_line and command_line != "-":
        cmd = command_line[:100] + "..." if len(command_line) > 100 else command_line
        parts.append(cmd)

    if target_path and target_path != "-" and not command_line:
        parts.append(target_path)

    if not parts and search_blob:
        blob_preview = search_blob[:150] + "..." if len(search_blob) > 150 else search_blob
        return blob_preview

    return " | ".join(parts) if parts else "-"
