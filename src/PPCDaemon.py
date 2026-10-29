#!/usr/bin/python3
"""Pardus Parental Control - System Daemon

Runs as root (systemd system service: ppc-daemon.service), completely outside
of user sessions, so it can not be killed by restricted users and it does not
block session logout.

Responsibilities:
 - Watches logind (system bus) for session new/remove and seat0 active
   session changes; applies/clears application + website filters accordingly.
 - Logs session usage minutes of restricted users (UsageLogger).
 - Checks session time limits once per minute. When the time is up:
     1. Emits the "SessionTimeExpired" D-Bus signal on the system bus.
        PPCAgent (running inside the user session) catches it and shows the
        countdown popup (NotificationApp).
     2. Terminates the user's sessions via logind after the countdown.
"""

import datetime
import logging
import os
import sys

from gi.repository import Gio, GLib  # noqa

import managers.PreferencesManager as PreferencesManager
import managers.SessionTimeManager as SessionTimeManager
import managers.UsageLogger as UsageLogger

logging.basicConfig(
    filename="/var/log/pardus-parental-control.log",
    level=logging.DEBUG,
    format="(%(asctime)s) [%(levelname)s]: %(message)s",
)

BUS_NAME = "tr.org.pardus.ParentalControl"
OBJECT_PATH = "/tr/org/pardus/ParentalControl"
INTERFACE_NAME = "tr.org.pardus.ParentalControl"

DBUS_INTERFACE_XML = """
<node>
  <interface name="tr.org.pardus.ParentalControl">
    <signal name="SessionTimeExpired">
      <arg name="uid" type="u"/>
      <arg name="username" type="s"/>
      <arg name="seconds_left" type="u"/>
    </signal>
    <method name="GetExpiryInfo">
      <arg name="expired" type="b" direction="out"/>
      <arg name="seconds_left" type="u" direction="out"/>
    </method>
  </interface>
</node>
"""

LOGIND_BUS = "org.freedesktop.login1"
LOGIND_PATH = "/org/freedesktop/login1"
LOGIND_MANAGER_IFACE = "org.freedesktop.login1.Manager"
LOGIND_SESSION_IFACE = "org.freedesktop.login1.Session"
LOGIND_SEAT0_PATH = "/org/freedesktop/login1/seat/seat0"
LOGIND_SEAT_IFACE = "org.freedesktop.login1.Seat"

# Seconds the PPCAgent shows the countdown popup before triggering a clean
# desktop-environment logout. Sent to the agent via the signal / GetExpiryInfo.
NOTIFY_SECONDS = 10

# Fallback: if the agent's clean logout does not happen (unknown desktop, or
# the agent was killed), the daemon force-terminates the session this many
# seconds after the expiry started. It must be long enough to cover the agent's
# startup delay + the popup + the desktop teardown, so it does not pre-empt a
# clean logout that is on its way.
FORCE_TERMINATE_SECONDS = 25


def _filter_manager():
    # Lazy import: FilterManager transitively imports Malcontent and
    # AccountsService which D-Bus activate accounts-daemon. Importing on
    # first use keeps the daemon startup at boot fast and safe.
    import managers.FilterManager as FilterManager

    return FilterManager


class SessionInfo:
    def __init__(self, session_id, object_path, uid, username):
        self.session_id = session_id
        self.object_path = object_path
        self.uid = uid
        self.username = username


class UsageInfo:
    def __init__(self, uid):
        self.uid = uid
        self.minutes = 0
        self.day = SessionTimeManager.now().date()


class PPCDaemon:
    def __init__(self):
        self.preferences_manager = PreferencesManager.get_default()

        self.bus = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)

        self.sessions = {}  # object_path -> SessionInfo (Class == "user" only)
        self.usage = {}  # username -> UsageInfo
        self.expiring = set()  # usernames whose time is up (popup -> logout)
        self.filters_cleared = False
        self.prefs_changed_timeout = None

    # == Setup ==
    def run(self):
        self.log("=== PPC Daemon Started ===")

        self.own_bus_name()
        self.connect_logind_signals()
        self.connect_seat_active_session()
        self.watch_preferences_file()

        # The daemon may (re)start while sessions are already open
        self.enumerate_existing_sessions()
        self.apply_for_active_seat_session()

        GLib.timeout_add_seconds(60, self.on_minute_tick)

        GLib.MainLoop().run()

    def own_bus_name(self):
        node_info = Gio.DBusNodeInfo.new_for_xml(DBUS_INTERFACE_XML)
        self.bus.register_object(
            OBJECT_PATH, node_info.interfaces[0], self.on_method_call, None
        )

        Gio.bus_own_name_on_connection(
            self.bus, BUS_NAME, Gio.BusNameOwnerFlags.NONE, None, None
        )

    def on_method_call(
        self, _conn, sender, _path, _iface, method_name, _params, invocation
    ):
        if method_name == "GetExpiryInfo":
            # PPCAgent asks this on startup: the expiry may have started at
            # login, before the agent itself (so the signal was missed).
            # The caller's uid is resolved from the bus, it can not be spoofed.
            try:
                uid = self.get_sender_uid(sender)
            except GLib.Error as e:
                invocation.return_dbus_error(f"{INTERFACE_NAME}.Error", e.message)
                return

            expired = self.is_uid_expiring(uid)

            invocation.return_value(
                GLib.Variant("(bu)", (expired, NOTIFY_SECONDS if expired else 0))
            )

    def get_sender_uid(self, sender):
        result = self.bus.call_sync(
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
            "GetConnectionUnixUser",
            GLib.Variant("(s)", (sender,)),
            GLib.VariantType("(u)"),
            Gio.DBusCallFlags.NONE,
            -1,
            None,
        )
        return result.unpack()[0]

    def is_uid_expiring(self, uid):
        """Whether the user with this uid is currently in the expiry process."""
        for username in self.expiring:
            usage = self.usage.get(username)
            if usage is not None and usage.uid == uid:
                return True

        return False

    def connect_logind_signals(self):
        self.bus.signal_subscribe(
            LOGIND_BUS,
            LOGIND_MANAGER_IFACE,
            "SessionNew",
            LOGIND_PATH,
            None,
            Gio.DBusSignalFlags.NONE,
            self.on_session_new,
        )
        self.bus.signal_subscribe(
            LOGIND_BUS,
            LOGIND_MANAGER_IFACE,
            "SessionRemoved",
            LOGIND_PATH,
            None,
            Gio.DBusSignalFlags.NONE,
            self.on_session_removed,
        )

    def connect_seat_active_session(self):
        self.seat_proxy = Gio.DBusProxy.new_sync(
            self.bus,
            Gio.DBusProxyFlags.DO_NOT_AUTO_START,
            None,
            LOGIND_BUS,
            LOGIND_SEAT0_PATH,
            LOGIND_SEAT_IFACE,
            None,
        )
        self.seat_proxy.connect("g-properties-changed", self.seat_properties_changed)

        self.log(" - Seat Check DBus Connected.")

    def watch_preferences_file(self):
        prefs_file = Gio.File.new_for_path(PreferencesManager.PREFERENCES_PATH)
        self.prefs_monitor = prefs_file.monitor_file(Gio.FileMonitorFlags.NONE, None)
        self.prefs_monitor.connect("changed", self.on_preferences_file_changed)

    def enumerate_existing_sessions(self):
        result = self.bus.call_sync(
            LOGIND_BUS,
            LOGIND_PATH,
            LOGIND_MANAGER_IFACE,
            "ListSessions",
            None,
            GLib.VariantType("(a(susso))"),
            Gio.DBusCallFlags.NONE,
            -1,
            None,
        )
        for (_id, _uid, _user, _seat, object_path) in result.unpack()[0]:
            self.track_session(object_path)

    # == Session Tracking ==
    def track_session(self, object_path):
        if object_path in self.sessions:
            return self.sessions[object_path]

        try:
            result = self.bus.call_sync(
                LOGIND_BUS,
                object_path,
                "org.freedesktop.DBus.Properties",
                "GetAll",
                GLib.Variant("(s)", (LOGIND_SESSION_IFACE,)),
                GLib.VariantType("(a{sv})"),
                Gio.DBusCallFlags.NONE,
                -1,
                None,
            )
        except GLib.Error as e:
            self.log(f"Could not read session properties of {object_path}: {e.message}")
            return None

        props = result.unpack()[0]

        # Ignore greeter (e.g. Debian-gdm) and "manager" (Pardus 25) sessions
        if props.get("Class") != "user":
            return None

        # Ignore sessions that are already logging out. Tracking one would
        # leave a stale entry: its SessionRemoved may already be emitted.
        if props.get("State") == "closing":
            return None

        (uid, _user_path) = props.get("User")
        info = SessionInfo(props.get("Id"), object_path, uid, props.get("Name"))
        self.sessions[object_path] = info

        self.log(f"Session tracked: {info.username}@{info.session_id}")

        if self.is_restricted(info.username):
            self.start_usage_tracking(info)

            # Kick out immediately if the session time is already over,
            # do not wait for the next minute tick.
            self.check_user_session_time(info.username, info.uid)

        return info

    def start_usage_tracking(self, info):
        if info.username in self.usage:
            return

        UsageLogger.save_login_timestamp(info.username)
        self.usage[info.username] = UsageInfo(info.uid)

        self.log(f" - Usage tracking started for '{info.username}'.")

    def on_session_new(self, _conn, _sender, _path, _iface, _signal, params):
        (_session_id, object_path) = params.unpack()
        self.track_session(object_path)
        self.apply_for_active_seat_session()

    def on_session_removed(self, _conn, _sender, _path, _iface, _signal, params):
        (_session_id, object_path) = params.unpack()

        if self.untrack_session(object_path):
            self.apply_for_active_seat_session()

    def untrack_session(self, object_path):
        info = self.sessions.pop(object_path, None)
        if info is None:
            return False

        self.log(f"Session removed: {info.username}@{info.session_id}")

        # Stop usage tracking if it was the user's last session
        if not any(s.username == info.username for s in self.sessions.values()):
            self.usage.pop(info.username, None)
            self.expiring.discard(info.username)
            self.log(f" - Usage tracking stopped for '{info.username}'.")

        return True

    def validate_tracked_sessions(self):
        """Self-heal: drop tracked sessions that no longer exist in logind
        (e.g. a missed SessionRemoved) or that are stuck in 'closing' state,
        so a logged out user is not tried to be terminated again and again."""
        for object_path in list(self.sessions):
            state = self.get_session_state(object_path)
            if state is None or state == "closing":
                self.untrack_session(object_path)

        # Drop usage entries that have no tracked session left
        tracked_usernames = {s.username for s in self.sessions.values()}
        for username in list(self.usage):
            if username not in tracked_usernames:
                del self.usage[username]
                self.expiring.discard(username)
                self.log(f" - Usage tracking stopped for '{username}' (no session).")

    def get_session_state(self, object_path):
        """Returns the logind session State ("online", "active", "closing")
        or None if the session does not exist anymore."""
        try:
            result = self.bus.call_sync(
                LOGIND_BUS,
                object_path,
                "org.freedesktop.DBus.Properties",
                "Get",
                GLib.Variant("(ss)", (LOGIND_SESSION_IFACE, "State")),
                GLib.VariantType("(v)"),
                Gio.DBusCallFlags.NONE,
                -1,
                None,
            )
        except GLib.Error:
            return None

        return result.unpack()[0]

    # == Filters (applied for the active seat0 session only) ==
    def seat_properties_changed(self, _proxy, properties_changed, _invalidated):
        props = properties_changed.unpack()
        if "ActiveSession" in props:
            (session_id, _session_path) = props["ActiveSession"]
            self.log(f"Active Session Changed: {session_id}")
            self.apply_for_active_seat_session()

    def get_active_seat_session(self):
        active = self.seat_proxy.get_cached_property("ActiveSession")
        if active is None:
            return None

        (session_id, object_path) = active.unpack()
        if not session_id or object_path == "/":
            return None

        return self.track_session(object_path)

    def apply_for_active_seat_session(self):
        info = self.get_active_seat_session()

        if info is not None and self.is_restricted(info.username):
            self.log(f"Applying preferences of '{info.username}'...")
            _filter_manager().apply_preferences(info.username, info.uid)
            self.filters_cleared = False
        elif not self.filters_cleared:
            self.log("No restricted user active. Clearing all filters.")
            _filter_manager().clear_all_filters()
            self.filters_cleared = True

    def is_restricted(self, username):
        self.preferences_manager.update_json_from_file()
        return self.preferences_manager.has_user(username)

    # == Preferences file watch ==
    def on_preferences_file_changed(self, _monitor, _file, _other_file, _event_type):
        # Debounce: the GUI may trigger multiple change events in a row
        if self.prefs_changed_timeout is not None:
            GLib.Source.remove(self.prefs_changed_timeout)

        self.prefs_changed_timeout = GLib.timeout_add_seconds(
            1, self.on_preferences_changed
        )

    def on_preferences_changed(self):
        self.prefs_changed_timeout = None

        self.log("Preferences changed. Refreshing...")

        # Start/stop usage tracking of already logged in users
        for info in list(self.sessions.values()):
            if self.is_restricted(info.username):
                self.start_usage_tracking(info)

                # The user may become out of the permitted range with the
                # new preferences, check immediately.
                self.check_user_session_time(info.username, info.uid)

        for username in list(self.usage):
            if not self.is_restricted(username):
                del self.usage[username]
                self.log(f" - Usage tracking stopped for '{username}'.")

        self.apply_for_active_seat_session()

        return GLib.SOURCE_REMOVE

    # == Session Time Control ==
    def on_minute_tick(self):
        self.validate_tracked_sessions()

        for username in list(self.usage):
            usage = self.usage[username]

            # The daily limit only counts sessions that started today. Start a
            # new log line after midnight, otherwise a session left open from
            # the day before is never counted for the new day.
            today = SessionTimeManager.now().date()
            if usage.day != today:
                UsageLogger.save_login_timestamp(username)
                usage.minutes = 0
                usage.day = today

            usage.minutes += 1
            UsageLogger.set_minutes_of_last_session(username, usage.minutes)

            self.check_user_session_time(username, usage.uid)

        return GLib.SOURCE_CONTINUE

    def check_user_session_time(self, username, uid):
        if username in self.expiring:
            return

        if self.is_session_time_ended(username):
            self.start_expiry(username, uid)

    def get_today_session_time_preferences(self, username):
        pref = self.preferences_manager.get_user(username).get_daily_usage()

        # Get index of the day:
        # 0: Monday ... 6:Sunday
        day_index = datetime.datetime.today().weekday()

        active = pref.get_active(day_index)
        start = pref.get_start(day_index)
        end = pref.get_end(day_index)
        limit = pref.get_limit(day_index)

        return (active, start, end, limit)

    def is_session_time_ended(self, username):
        if not self.is_restricted(username):
            return False

        (active, start, end, limit) = self.get_today_session_time_preferences(username)

        if not active:
            return False

        # Permitted time range check. Session Time Minutes: [0, 1439].
        # start == end means no time range is set, only the limit applies.
        if start != end:
            now_minutes = SessionTimeManager.now_minutes()
            if now_minutes < start or now_minutes > end:
                self.log(
                    f"=== Session time of '{username}' is up! (outside of {start}-{end}) ==="
                )
                return True

        # Daily usage limit check, independent of the time range.
        # limit == 0 means unlimited.
        if limit != 0:
            today_elapsed_minutes = SessionTimeManager.get_today_session_usage_minutes(
                username
            )
            if today_elapsed_minutes > limit:
                self.log(
                    f"=== Session time of '{username}' is up! (usage {today_elapsed_minutes} > limit {limit}) ==="
                )
                return True

        print(f"Session time of '{username}' not ended yet")
        return False

    def start_expiry(self, username, uid):
        self.expiring.add(username)

        self.log(f" - Notifying '{username}': session ends in {NOTIFY_SECONDS} seconds.")

        # The agent shows the popup and triggers a clean logout. If it already
        # runs it gets this signal; if the expiry started at login (before the
        # agent), the agent learns it on startup via GetExpiryInfo instead.
        self.bus.emit_signal(
            None,  # broadcast
            OBJECT_PATH,
            INTERFACE_NAME,
            "SessionTimeExpired",
            GLib.Variant("(usu)", (uid, username, NOTIFY_SECONDS)),
        )

        # Fallback in case the clean logout does not happen.
        GLib.timeout_add_seconds(
            FORCE_TERMINATE_SECONDS, self.force_terminate, username
        )

    def force_terminate(self, username):
        # The agent's clean desktop logout should have closed the session by
        # now. If the user logged out (cleanly or otherwise), it is no longer
        # in self.expiring and there is nothing to do.
        if username not in self.expiring:
            self.log(f" - '{username}' already logged out, no termination needed.")
            return GLib.SOURCE_REMOVE

        # The clean logout did not happen (unknown desktop, or the agent was
        # killed). Force the still-tracked sessions of the user to close.
        # TerminateSession (per session) matches what display managers do and
        # is gentler than TerminateUser, which also kills the user manager and
        # is more likely to leave a black screen on GDM + Wayland.
        sessions = [
            (object_path, info)
            for object_path, info in self.sessions.items()
            if info.username == username
        ]

        self.log(
            f" - Clean logout did not complete. Forcing termination of "
            f"'{username}' sessions: {[i.session_id for _, i in sessions]}"
        )

        for object_path, info in sessions:
            try:
                self.bus.call_sync(
                    LOGIND_BUS,
                    LOGIND_PATH,
                    LOGIND_MANAGER_IFACE,
                    "TerminateSession",
                    GLib.Variant("(s)", (info.session_id,)),
                    None,
                    Gio.DBusCallFlags.NONE,
                    -1,
                    None,
                )
            except GLib.Error as e:
                self.log(f"TerminateSession({info.session_id}) failed: {e.message}")

            # Untrack right away. logind keeps the terminated session in
            # "closing" state for a while, so waiting for SessionRemoved (or the
            # next minute tick) would leave a stale entry and confuse an
            # immediate re-login.
            self.untrack_session(object_path)

        self.apply_for_active_seat_session()

        self.expiring.discard(username)

        return GLib.SOURCE_REMOVE

    def log(self, msg):
        message = f"(ppc-daemon): {msg}"
        print(message)
        logging.info(message)


if __name__ == "__main__":
    if os.getuid() != 0:
        sys.stderr.write("This daemon must run as root.\n")
        sys.exit(1)

    daemon = PPCDaemon()
    daemon.run()
