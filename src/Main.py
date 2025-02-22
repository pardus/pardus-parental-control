#!/usr/bin/python3
import gi
import sys
import managers.FileRestrictionManager as FileRestrictionManager

from ui.MainWindow import MainWindow

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Gtk, Gio, Adw  # noqa


class Main(Adw.Application):
    def __init__(self):
        super().__init__(
            application_id="tr.org.pardus.parental-control",
            flags=Gio.ApplicationFlags.DEFAULT_FLAGS,
        )

        self.window = None

    def do_activate(self):
        if self.window is None:
            self.window = MainWindow(self)

        self.window.show_ui()


# Privileged run check
if not FileRestrictionManager.check_user_privileged():
    sys.stderr.write("You are not privileged to run this script.\n")
    sys.exit(1)

app = Main()
app.run(sys.argv)
