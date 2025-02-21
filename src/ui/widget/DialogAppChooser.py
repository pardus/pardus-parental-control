import managers.ApplicationManager as ApplicationManager
import ui.widget.PActionRow as PActionRow

from locale import gettext as _

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Gtk, Adw, Gio, GLib  # noqa


class DialogAppChooser(Adw.PreferencesWindow):
    def __init__(self, application_selected_callback):
        super().__init__()

        self.setup_window()

        self.setup_ui()

        self.on_application_selected_callback = application_selected_callback

    # == SETUP ==
    def setup_window(self):
        self.set_default_size(450, 600)
        self.set_search_enabled(True)
        self.set_title(_("Select Application..."))
        self.set_hide_on_close(True)

    def setup_ui(self):
        group = Adw.PreferencesGroup(description=_("Loading..."))

        page = Adw.PreferencesPage()
        page.add(group)

        self.add(page)

        GLib.timeout_add(10, self.add_all_applications_to_group, group)

    # == FUNCTIONS ==
    def add_all_applications_to_group(self, group):
        for app in ApplicationManager.get_all_applications():
            action_row = PActionRow.new(
                title=app.get_name(),
                subtitle=app.get_id(),
                gicon=app.get_icon(),
                on_activated=self.on_action_application_selected,
                user_data=app,
            )

            group.add(action_row)

        group.set_description("")

    # == CALLBACKS ==
    def on_action_application_selected(self, action, app):
        self.on_application_selected_callback(app)

        self.close()
