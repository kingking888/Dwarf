"""
Dwarf - Copyright (C) 2019 Giovanni Rocca (iGio90)

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>
"""
import frida
import requests

from PyQt5.QtCore import Qt, QSize, QRect, pyqtSignal, QThread, QMargins
from PyQt5.QtGui import QFont, QPixmap, QIcon
from PyQt5.QtWidgets import QWidget, QDialog, QLabel, QVBoxLayout, QHBoxLayout, QPushButton, QListView, QSpacerItem, QSizePolicy, QStyle, qApp

from ui.dialog_js_editor import JsEditorDialog
from ui.list_pick import PickList
from ui.widget_android_package import AndroidPackageWidget
from ui.widget_item_not_editable import NotEditableListWidgetItem

from ui.processes_widget import ProcessList


class DevicesUpdateThread(QThread):
    """ Updates DeviceSelector
        signals:
            clear_devices()
            clear_procs()
            clear_spawns()
            add_device(devicename, customdata, currentitem)
            devices_updated()
    """
    clear_devices = pyqtSignal()
    clear_procs = pyqtSignal()
    clear_spawns = pyqtSignal()
    add_device = pyqtSignal(str, str, bool)
    devices_updated = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)

    def run(self):
        # clear lists
        self.clear_devices.emit()
        self.clear_procs.emit()
        self.clear_spawns.emit()

        # get frida devices
        devices = frida.enumerate_devices()

        for device in devices:
            device_string = ('Device: {0} - ({1})'.format(device.name, device.type))
            self.add_device.emit(device_string, device.id, device.type == 'usb')

        self.devices_updated.emit()


class SpawnsThread(QThread):
    """ Updates the SpawnsList
        signals:
            clear_proc()
            add_spawn(NotEditableListWidgetItem)
            is_error(str) - shows str in statusbar
        device must set before run
    """

    clear_spawns = pyqtSignal()
    add_spawn = pyqtSignal(NotEditableListWidgetItem)
    is_error = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.device = None

    def run(self):

        self.clear_spawns.emit()

        if self.device is not None:
            try:
                apps = self.device.enumerate_applications()

                last_letter = ''

                for app in sorted(apps, key=lambda x: x.name):
                    app_name = app.name
                    letter = app.name[0].upper()

                    if last_letter != letter:
                        if last_letter != '':
                            item = NotEditableListWidgetItem('')
                            item.setFlags(Qt.NoItemFlags)
                            self.add_spawn.emit(item)

                        last_letter = letter
                        item = NotEditableListWidgetItem(last_letter)
                        item.setFlags(Qt.NoItemFlags)
                        self.add_spawn.emit(item)

                    item = AndroidPackageWidget(app_name, app.identifier, 0)
                    self.add_spawn.emit(item)
            except frida.ServerNotRunningError:
                self.is_error.emit('unable to connect to remote frida server: not started')
            except frida.TransportError:
                self.is_error.emit('unable to connect to remote frida server: closed')
            except frida.TimedOutError:
                self.is_error.emit('unable to connect to remote frida server: timedout')
            except Exception:
                self.is_error.emit('something was wrong...')

        self.device = None


class DeviceWindow(QDialog):

    onSelectedProcess = pyqtSignal(int, name='onSelectedProcess')

    def __init__(self, parent=None, device='local'):
        super(DeviceWindow, self).__init__(parent=parent)
        self.setModal(True)

        if device == 'local':
            self.device = frida.get_local_device()
        elif device == 'usb':
            self.device = frida.get_usb_device()
        else:
            self.device = frida.get_local_device()

        self.updated_frida_version = ''
        self.updated_frida_assets_url = {}

        self.frida_update_thread = None
        self.devices_thread = None
        self.procs_update_thread = None
        self.spawns_update_thread = None

        #frida.get_device_manager().on('added', self.update_device_ui)
        #frida.get_device_manager().on('removed', self.update_device_ui)

        self.setup_ui()
        self.setup_threads()

    def setup_ui(self):

        # procs/spawns lists
        spawns_vbox = QVBoxLayout()

        spawns_label = QLabel('SPAWN')
        spawns_label.setFont(QFont('Anton', 20, QFont.Normal))
        spawns_vbox.addWidget(spawns_label)

        self.spawn_list = PickList(self.on_spawn_picked)
        spawns_vbox.addWidget(self.spawn_list)

        spawns_refresh_button = QPushButton('refresh')
        # spawns_refresh_button.clicked.connect(self.on_refresh_spawns)
        spawns_vbox.addWidget(spawns_refresh_button)

        procs_vbox = QVBoxLayout()

        procs_label = QLabel('PROCS')
        procs_label.setFont(QFont('Anton', 20, QFont.Normal))
        procs_vbox.addWidget(procs_label)

        #self.proc_list = PickList(self.on_proc_picked)
        #devices = frida.enumerate_devices()
        self.proc_list = ProcessList(device=self.device)
        self.proc_list.onProcessSelected.connect(self._pid_selected)
        procs_vbox.addWidget(self.proc_list)

        #procs_refresh_button = QPushButton('refresh')
        # procs_refresh_button.clicked.connect(self.on_refresh_procs)
        # procs_vbox.addWidget(procs_refresh_button)

        inner_hbox = QHBoxLayout()
        inner_hbox.addLayout(spawns_vbox)
        inner_hbox.addLayout(procs_vbox)
        self.setLayout(inner_hbox)

    # onshow start thread
    def showEvent(self, QShowEvent):
        super().showEvent(QShowEvent)

    def setup_threads(self):
        """ Setups the Threads used here
        """
        """
        if self.devices_thread is None:
            self.devices_thread = DevicesUpdateThread(self.app)
            self.devices_thread.add_device.connect(self.on_add_deviceitem)
            self.devices_thread.clear_devices.connect(self.on_clear_devicelist)
            self.devices_thread.clear_procs.connect(self.on_clear_proclist)
            self.devices_thread.clear_spawns.connect(self.on_clear_spawnlist)
            self.devices_thread.devices_updated.connect(self.on_devices_updated)

        if self.spawns_update_thread is None:
            self.spawns_update_thread = SpawnsThread(self)
            self.spawns_update_thread.add_spawn.connect(self.on_add_spawn)
            self.spawns_update_thread.clear_spawns.connect(self.on_clear_spawnlist)
            self.spawns_update_thread.is_error.connect(self.on_status_text)"""

    def _pid_selected(self, pid):
        if pid:
            self.onSelectedProcess.emit(pid[0])
            self.accept()

    def on_proc_picked(self, widget_android_package):
        editor = JsEditorDialog(self.app, def_text=self.startup_script,
                                placeholder_text='// Javascript with frida and dwarf api to run at injection')
        accept, what = editor.show()
        if accept:
            self.startup_script = what
            app_name = widget_android_package.appname
            app_pid = widget_android_package.get_pid()
            if "\t" in app_name:
                app_name = app_name.split("\t")[1]

            self.app.get_dwarf().attach(app_pid, script=what)
            self.app.get_dwarf().app_window.update_title("Dwarf - Attached to %s (pid %s)" % (app_name, app_pid))

    def on_spawn_picked(self, widget_android_package):
        editor = JsEditorDialog(self.app, def_text=self.startup_script,
                                placeholder_text='// Javascript with frida and dwarf api to run at injection')
        accept, what = editor.show()
        if accept:
            self.startup_script = what

            app_name = widget_android_package.appname
            package_name = widget_android_package.get_package_name()

            self.app.get_dwarf().spawn(package_name, script=what)
            self.app.get_dwarf().app_window.update_title("Dwarf - Attached to %s (%s)" % (app_name, package_name))
