import copy
import json
import os
from pathlib import Path


# Chromium based browsers read every json file in the managed directory, so we
# keep our own file and don't touch policies set by the system administrator.
CHROMIUM_POLICY_DIRS = [
    Path("/etc/opt/chrome/policies/managed"),
    Path("/etc/brave/policies/managed"),
    Path("/etc/chromium/policies/managed"),
    Path("/etc/chromium-browser/policies/managed"),
]
CHROMIUM_POLICY_FILENAME = "pardus-parental-control.json"
# Older versions wrote to this file
CHROMIUM_LEGACY_POLICY_FILENAME = "policies.json"

# Firefox only reads a single policies.json, our keys are merged into it.
FIREFOX_POLICY_PATH = Path("/usr/share/firefox-esr/distribution/policies.json")

CHROME_POLICY_JSON = {
    "URLBlocklist": [],  # e.g. "google.com", "*" to block everything, "youtube.com"
    "URLAllowlist": [],
    "DnsOverHttpsMode": "off",
}

# These keys will be appended/removed in the json.
FIREFOX_POLICY_JSON = {
    "policies": {
        "WebsiteFilter": {
            # https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Match_patterns
            "Block": [],  # eg "<all_urls>"
            "Exceptions": [],  # eg "*://*.youtube.com/*", "*://*.pardus.org.tr/*"
        },
        "DNSOverHTTPS": {"Enabled": False, "Locked": True},
    }
}


def _generate_chromium_policy(domain_list, is_allowlist):
    chromium_policy_object = copy.deepcopy(CHROME_POLICY_JSON)

    if is_allowlist:
        # Block everything except allowlist
        chromium_policy_object["URLBlocklist"] = ["*"]
        chromium_policy_object["URLAllowlist"] = domain_list
    else:
        chromium_policy_object["URLAllowlist"] = []
        chromium_policy_object["URLBlocklist"] = domain_list

    return chromium_policy_object


def _generate_firefox_policy(domain_list, is_allowlist):
    obj = copy.deepcopy(FIREFOX_POLICY_JSON)

    if is_allowlist:
        # Block everything except allowlist
        # convert e.g. "google.com" -> "*://*.google.com/*"
        new_domain_list = []
        for d in domain_list:
            new_domain_list.append("http://*.{}/*".format(d))
            new_domain_list.append("https://*.{}/*".format(d))

        obj["policies"]["WebsiteFilter"]["Block"] = ["<all_urls>"]
        obj["policies"]["WebsiteFilter"]["Exceptions"] = new_domain_list
    else:
        # convert e.g. "google.com" -> "*://*.google.com/*"
        new_domain_list = []
        for d in domain_list:
            new_domain_list.append("http://*.{}/*".format(d))
            new_domain_list.append("https://*.{}/*".format(d))

        obj["policies"]["WebsiteFilter"]["Block"] = new_domain_list
        del obj["policies"]["WebsiteFilter"]["Exceptions"]

    return obj


def _load_browser_policy(browser_config_path: Path):
    try:
        with open(browser_config_path, "r") as file1:
            return json.load(file1)
    except (OSError, ValueError):
        return None


def _save_browser_policy(browser_config_path: Path, policy_json_object):
    if not browser_config_path.exists():
        browser_config_path.parent.mkdir(parents=True, exist_ok=True)
        browser_config_path.touch()

    with open(browser_config_path, "w") as file1:
        json_text = json.dumps(
            policy_json_object,
            ensure_ascii=False,
            indent=4,
            sort_keys=True,
        )

        json_text += "\n"
        file1.write(json_text)

    print("Browser Policy Saved:{}".format(browser_config_path))


def create_browser_config(domain_list, is_allowlist):
    chromium_policy = _generate_chromium_policy(domain_list, is_allowlist)
    firefox_policy = _generate_firefox_policy(domain_list, is_allowlist)

    # Save for all browsers
    for policy_dir in CHROMIUM_POLICY_DIRS:
        _remove_legacy_chromium_policy(policy_dir)
        _save_browser_policy(policy_dir / CHROMIUM_POLICY_FILENAME, chromium_policy)

    # Keep the other Firefox policies, only replace our keys
    existing = _load_browser_policy(FIREFOX_POLICY_PATH)
    if not isinstance(existing, dict):
        existing = {}
    existing.setdefault("policies", {}).update(firefox_policy["policies"])
    _save_browser_policy(FIREFOX_POLICY_PATH, existing)


def remove_browser_config():
    for policy_dir in CHROMIUM_POLICY_DIRS:
        _remove_legacy_chromium_policy(policy_dir)
        _remove_file_if_exists(policy_dir / CHROMIUM_POLICY_FILENAME)

    existing = _load_browser_policy(FIREFOX_POLICY_PATH)
    if not isinstance(existing, dict):
        _remove_file_if_exists(FIREFOX_POLICY_PATH)
        return

    policies = existing.get("policies", {})
    for key in FIREFOX_POLICY_JSON["policies"]:
        policies.pop(key, None)

    if policies or len(existing) > 1:
        _save_browser_policy(FIREFOX_POLICY_PATH, existing)
    else:
        _remove_file_if_exists(FIREFOX_POLICY_PATH)


def _remove_legacy_chromium_policy(policy_dir):
    # Only remove the old file if it has nothing but our own keys
    legacy_path = policy_dir / CHROMIUM_LEGACY_POLICY_FILENAME
    legacy = _load_browser_policy(legacy_path)
    if isinstance(legacy, dict) and legacy and set(legacy) <= set(CHROME_POLICY_JSON):
        _remove_file_if_exists(legacy_path)


def _remove_file_if_exists(path):
    if os.path.exists(path):
        os.remove(path)
        print("Removed: {}".format(path))
