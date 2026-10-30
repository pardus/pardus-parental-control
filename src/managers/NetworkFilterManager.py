import subprocess

import managers.SmartdnsManager as SmartdnsManager
import managers.BrowserManager as BrowserManager

RESOLV_CONF_PATH = "/etc/resolv.conf"
RESOLV_CONF_CONTENT = """# This file is generated & locked by pardus-parental-control app. Please do not change.

nameserver 127.0.0.1

"""


def read_resolvconf_dns_servers():
    dns_servers = []
    with open(RESOLV_CONF_PATH, "r") as file1:
        for line in file1.readlines():
            uncommented_line = line.strip().split("#")[0]

            if "nameserver" in line:
                server = uncommented_line.strip().split(" ")[-1]
                dns_servers.append(server)

    return dns_servers


def set_resolvconf_to_localhost():
    subprocess.run(["chattr", "-i", "/etc/resolv.conf"])  # unblock file

    with open(RESOLV_CONF_PATH, "w") as file1:
        file1.write(RESOLV_CONF_CONTENT)

    subprocess.run(["chattr", "+i", "/etc/resolv.conf"])  # block file


def resolvconf_is_ours():
    try:
        with open(RESOLV_CONF_PATH, "r") as file1:
            return file1.readline() == RESOLV_CONF_CONTENT.splitlines(True)[0]
    except OSError:
        return False


def reset_resolvconf_to_default():
    subprocess.run(["chattr", "-i", "/etc/resolv.conf"])  # unblock file
    subprocess.run(["rm", "/etc/resolv.conf"])  # delete file
    subprocess.run(
        ["systemctl", "restart", "NetworkManager.service"]
    )  # generate new resolvconf from network manager


def apply_domain_filter_list(domain_list, is_allowlist, dns_servers):
    # /etc/resolv.conf
    set_resolvconf_to_localhost()

    # /etc/smartdns/smartdns.conf
    SmartdnsManager.create_smartdns_config(domain_list, is_allowlist, dns_servers)

    # Service
    if SmartdnsManager.enable_smartdns_service().returncode != 0:
        SmartdnsManager.install_smartdns_service()
        SmartdnsManager.enable_smartdns_service()
    SmartdnsManager.restart_smartdns_service()

    # Browser Policies
    BrowserManager.create_browser_config(domain_list, is_allowlist)


def clear_domain_filter_list():
    # /etc/resolv.conf, only if we wrote it. This also runs at every daemon
    # start, it shouldn't delete a resolv.conf the admin made and restart
    # NetworkManager when no filter was applied.
    if resolvconf_is_ours():
        reset_resolvconf_to_default()

    # /etc/smartdns/smartdns.conf
    SmartdnsManager.remove_smartdns_config()

    # Service
    SmartdnsManager.stop_smartdns_service()
    SmartdnsManager.disable_smartdns_service()

    # Browser Policies
    BrowserManager.remove_browser_config()
