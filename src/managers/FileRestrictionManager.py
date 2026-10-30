import os
import stat
import subprocess

PRIVILEGED_GROUP = "sudo"
PRIVILEGED_GROUP_ID = int(
    subprocess.check_output(["getent", "group", PRIVILEGED_GROUP])
    .decode()
    .split(":")[2]
)


def check_user_privileged():
    if os.getuid() == 0:  # root user
        return True

    user_groups = os.getgroups()
    if PRIVILEGED_GROUP_ID in user_groups:  # not root but in the group
        return True

    return False


# Restrict
def restrict_bin_file(filepath):
    if filepath:
        os.chmod(filepath, 0o750)  # rwxr-x---
        os.chown(filepath, 0, PRIVILEGED_GROUP_ID)  # root:sudo


def restrict_desktop_file(filepath):
    if filepath:
        os.chmod(filepath, 0o640)  # rw-r-----
        os.chown(filepath, 0, PRIVILEGED_GROUP_ID)


def restrict_conf_file(filepath):
    restrict_desktop_file(filepath)


def _restricted_by_us(filepath, mode):
    # Clearing the filters runs for every application (also at every daemon
    # start), so only revert files that look like restrict_*() left them.
    # Others (setuid binaries, apps owned by a user in /opt...) stay as is.
    try:
        st = os.stat(filepath)
    except OSError:
        return False
    return st.st_gid == PRIVILEGED_GROUP_ID and stat.S_IMODE(st.st_mode) == mode


# Unrestrict
def unrestrict_conf_file(filepath):
    unrestrict_desktop_file(filepath)  # same permission style


def unrestrict_desktop_file(filepath):
    if filepath and _restricted_by_us(filepath, 0o640):
        os.chmod(filepath, 0o644)  # rw-r--r--
        os.chown(filepath, 0, 0)  # root:root


def unrestrict_bin_file(filepath):
    if filepath and _restricted_by_us(filepath, 0o750):
        os.chmod(filepath, 0o755)  # rwxr-xr-x
        os.chown(filepath, 0, 0)  # root:root
