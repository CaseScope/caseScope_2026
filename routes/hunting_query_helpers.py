"""Shared helpers for hunting query routes."""

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
) -> str:
    """Build an inclusive OR filter over the selected alert-type checkboxes."""
    selected_conditions = []

    if sigma_filter_param != "exclude":
        selected_conditions.append(_build_sigma_alert_condition(severity_levels_param))

    if ioc_filter_param != "exclude":
        selected_conditions.append("length(ioc_types) > 0")

    if analyst_filter_param != "exclude":
        selected_conditions.append("analyst_tagged = true")

    if other_filter_param != "exclude":
        selected_conditions.append(
            f"(NOT {SIGMA_EVENT_CONDITION} AND length(ioc_types) = 0 AND analyst_tagged = false)"
        )

    if not selected_conditions:
        return " AND 1=0"

    return f" AND ({' OR '.join(selected_conditions)})"


def build_event_description(artifact_type, channel, provider, username, process_name, command_line, target_path, search_blob):
    """Build a human-readable description for an event."""
    parts = []

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
