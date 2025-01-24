#!/usr/bin/python3

import sys
import subprocess
import time

import managers.FileRestrictionManager as FileRestrictionManager
import managers.LinuxUserManager as LinuxUserManager
import managers.PreferencesManager as PreferencesManager
import managers.NetworkFilterManager as NetworkFilterManager
import managers.ApplicationManager as ApplicationManager
import managers.SmartdnsManager as SmartdnsManager


import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Gtk, Gio, GLib, Adw  # noqa


import locale  # noqa
from locale import gettext as _  # noqa

# Translation Constants:
APPNAME = "pardus-parental-control"
TRANSLATIONS_PATH = "/usr/share/locale"

# Translation functions:
locale.bindtextdomain(APPNAME, TRANSLATIONS_PATH)
locale.textdomain(APPNAME)


class NotificationApp(Gtk.Application):
    def __init__(self):
        super().__init__(
            application_id="tr.org.pardus.parental-control",
            flags=Gio.ApplicationFlags.DEFAULT_FLAGS,
        )

        self.logged_user_name = LinuxUserManager.get_active_session_username()
        self.seconds_left = 10

    def do_activate(self):
        self.setup_window()

        GLib.timeout_add_seconds(1, self.tick_logout_seconds)

    def tick_logout_seconds(self):
        self.seconds_left -= 1
        self.subtitle.set_text(
            _("Session will be closed in {} seconds.").format(self.seconds_left)
        )

        if self.seconds_left == 0:
            subprocess.Popen(["loginctl", "kill-user", self.logged_user_name])
            sys.exit(0)
            # return False  # stop looping

        return True

    def setup_window(self):
        window = Adw.Window(application=self)
        window.set_default_size(500, 200)
        window.set_icon_name("pardus-parental-control")
        window.set_hide_on_close(True)

        # UI
        ui = self.setup_ui()

        window.set_content(ui)
        window.present()

    def setup_ui(self):
        user = LinuxUserManager.get_user_object(self.logged_user_name)
        real_name = user.get_real_name()

        session_avatar = Gtk.Box(
            spacing=7, halign=Gtk.Align.CENTER, css_classes=["card"]
        )
        session_avatar.append(
            Adw.Avatar(
                text=real_name,
                halign=Gtk.Align.START,
                size=32,
                margin_start=7,
                margin_top=7,
                margin_bottom=7,
            )
        )
        session_avatar.append(
            Gtk.Label(label=real_name, halign=Gtk.Align.START, margin_end=7)
        )

        title = Gtk.Label(
            label=_("Your session time is over."),
            css_classes=["title-2"],
            justify=Gtk.Justification.CENTER,
            margin_top=14,
        )
        self.subtitle = Gtk.Label(
            label=_("Session will be closed in {} seconds.").format(self.seconds_left),
            justify=Gtk.Justification.CENTER,
        )
        box = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL,
            valign=Gtk.Align.CENTER,
            spacing=7,
        )
        box.append(session_avatar)
        box.append(title)
        box.append(self.subtitle)

        return box


class PPCActivator(Gio.Application):
    def __init__(self):
        # Privileged run check
        if not FileRestrictionManager.check_user_privileged():
            sys.stderr.write("You are not privileged to run this script.\n")
            sys.exit(1)

        super().__init__(
            application_id="tr.org.pardus.parental-control.apply-settings",
            flags=Gio.ApplicationFlags.DEFAULT_FLAGS,
        )

    def do_activate(self):
        print("== PPCActivator STARTED ==")

        self.logged_user_name = LinuxUserManager.get_active_session_username()
        self.logged_user = LinuxUserManager.get_user_object(self.logged_user_name)

        self.read_user_preferences()

        if self.preferences.get_is_application_filter_active():
            self.apply_application_filter()
        else:
            self.clear_application_filter()

        if self.preferences.get_is_website_filter_active():
            self.apply_website_filter()
        else:
            self.clear_website_filter()

        if self.preferences.get_is_session_time_filter_active():
            self.start_session_time_checker()

        print("== PPCActivator FINISHED ==")

    def read_user_preferences(self):
        self.preferences_manager = PreferencesManager.get_default()
        if self.preferences_manager.has_user(self.logged_user_name):
            print("User found:", self.logged_user_name)
            self.preferences = self.preferences_manager.get_user(self.logged_user_name)
        else:
            self.clear_application_filter()
            self.clear_website_filter()
            print(
                "User not found in preferences.json: {}".format(self.logged_user_name)
            )
            print("Cleared all filters")
            sys.exit(0)

    # == Application Filtering ==
    def apply_application_filter(self):
        pref = self.preferences

        list_length = len(pref.get_application_list())
        if list_length == 0:
            return

        is_allowlist = pref.get_is_application_list_allowlist()
        if is_allowlist:
            for app in ApplicationManager.get_all_applications():
                if app.get_filename() in pref.get_application_list():
                    ApplicationManager.unrestrict_application(app.get_filename())
                else:
                    ApplicationManager.restrict_application(app.get_filename())
        else:
            for app_id in pref.get_application_list():
                ApplicationManager.restrict_application(app_id)

    def clear_application_filter(self):
        for app in ApplicationManager.get_all_applications():
            ApplicationManager.unrestrict_application(app.get_filename())

    # == Website Filtering ==
    def apply_website_filter(self):
        pref = self.preferences

        list_length = len(pref.get_website_list())
        if list_length == 0:
            return

        is_allowlist = pref.get_is_website_list_allowlist()

        # browser + domain configs
        NetworkFilterManager.apply_domain_filter_list(
            pref.get_website_list(),
            is_allowlist,
            self.preferences_manager.get_base_dns_servers(),
        )

    def clear_website_filter(self):
        # browser + domain configs
        NetworkFilterManager.clear_domain_filter_list()

    # == Session Time Control ==
    def start_session_time_checker(self):
        # Session Time Minutes. 1440 minutes in a day.
        start = self.preferences.get_session_time_start()
        end = self.preferences.get_session_time_end()

        if start == end:
            print("Configuration Start and End times are equal. Not applying.")
            return

        self.tick_session_time_check(start, end)

        GLib.timeout_add_seconds(60, self.tick_session_time_check, start, end)

        self.hold()

    def tick_session_time_check(self, start, end):
        t = time.localtime()
        minutes_now = (60 * t.tm_hour) + t.tm_min

        if minutes_now >= start and minutes_now <= end:
            print("Minutes left: ", end - minutes_now)
            return True

        print("Time is up! Shutting down...")

        # Time is up! -- Session time finished
        notify_app = NotificationApp()
        notify_app.run()

        return False


if __name__ == "__main__":
    activator = PPCActivator()
    if len(sys.argv) == 2:
        if sys.argv[1] == "--disable":
            activator.clear_application_filter()
            activator.clear_website_filter()
            sys.exit(0)

    activator.run()
