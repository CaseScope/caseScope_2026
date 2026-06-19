"""Helpers for classifying retained-only support files."""
import re


CHROME_EXTENSION_LOCALE_MESSAGES_RE = re.compile(
    r"/extensions/[^/]+/[^/]+/_locales/[^/]+/messages\.json$"
)
CHROME_EXTENSION_METADATA_RE = re.compile(
    r"/extensions/[^/]+/[^/]+/_metadata/(?:computed_hashes|verified_contents)\.json$"
)
BROWSER_EXTENSION_RESOURCE_JSON_RE = re.compile(
    r"/extensions/[^/]+/[^/]+/(?:browser/data|data/data/[^/]+|resources/).*/[^/]+\.json$"
)
BROWSER_EXTENSION_STATIC_ASSET_RE = re.compile(
    r"/extensions/[^/]+/[^/]+/.+\.(?:css|gif|htm|html|jpeg|jpg|js|map|mjs|png|svg|wasm)$"
)
FIREFOX_PROFILE_SUPPORT_JSON_FILENAMES = {
    'autofill-profiles.json',
    'broadcast-listeners.json',
    'experimentstoredata.json',
    'extension-settings.json',
    'logins-backup.json',
    'session-state.json',
    'shield-preference-experiments.json',
    'shield-recipe-client.json',
    'tabs.json',
    'targeting.snapshot.json',
    'taskbartabs.json',
}
EXPLORER_STARTUP_ETL_FILENAMES = {
    'explorerstartuplog.etl',
    'explorerstartuplog_runonce.etl',
}


def is_chrome_extension_locale_messages(filename: str) -> bool:
    """Return True for static Chrome/Edge extension localization resources."""
    if not filename:
        return False
    path_lower = filename.replace('\\', '/').lower()
    return bool(CHROME_EXTENSION_LOCALE_MESSAGES_RE.search(path_lower))


def is_browser_extension_support_json(filename: str) -> bool:
    """Return True for static browser extension resource metadata JSON."""
    if not filename:
        return False
    path_lower = filename.replace('\\', '/').lower()
    return bool(
        CHROME_EXTENSION_LOCALE_MESSAGES_RE.search(path_lower)
        or CHROME_EXTENSION_METADATA_RE.search(path_lower)
        or BROWSER_EXTENSION_RESOURCE_JSON_RE.search(path_lower)
    )


def is_browser_extension_static_asset(filename: str) -> bool:
    """Return True for packaged browser extension assets that are not timeline events."""
    if not filename:
        return False
    path_lower = filename.replace('\\', '/').lower()
    return bool(BROWSER_EXTENSION_STATIC_ASSET_RE.search(path_lower))


def is_firefox_profile_support_json(filename: str) -> bool:
    """Return True for Firefox profile JSON that is settings/state, not events."""
    if not filename:
        return False
    path_lower = filename.replace('\\', '/').lower()
    normalized = path_lower.split('/')[-1]
    return (
        '/mozilla/firefox/profiles/' in path_lower
        and normalized in FIREFOX_PROFILE_SUPPORT_JSON_FILENAMES
    )


def is_explorer_startup_etl(filename: str) -> bool:
    """Return True for Explorer startup ETLs that only produce metadata noise."""
    if not filename:
        return False
    normalized = filename.replace('\\', '/').lower().split('/')[-1]
    return normalized in EXPLORER_STARTUP_ETL_FILENAMES


def is_retained_support_file(filename: str) -> bool:
    """Return True for known low-value support files that should be retained only."""
    return (
        is_browser_extension_support_json(filename)
        or is_browser_extension_static_asset(filename)
        or is_firefox_profile_support_json(filename)
        or is_explorer_startup_etl(filename)
    )
