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
from PyQt5.QtWidgets import QMenu, QAction, QFileDialog

from lib.session import Session
from lib.android import AndroidDecompileUtil
from lib.adb import Adb

from ui.dialog_list import ListDialog
from ui.dialog_input import InputDialog

from ui.widget_android_package import AndroidPackageWidget
from ui.widget_item_not_editable import NotEditableListWidgetItem

from ui.device_window import DeviceWindow
from ui.apk_list import ApkListDialog


class AndroidSession(Session):
    """ All Android Stuff goes here
        if u look for something android related its here then
    """

    def __init__(self, app_window):
        super(AndroidSession, self).__init__(app_window)
        self._app_window = app_window

        self.adb = Adb()
        if not self.adb.is_available():
            print('No ADB available')
            return

        self._device_window = DeviceWindow(self._app_window, 'usb')

        # main menu every session needs
        self._menu = [QMenu(self.session_type + ' Session')]
        #self._menu[0].addAction('Save Session', self._save_session)
        self._menu[0].addAction('Close Session', self.stop_session)

        # connect to onUiReady so we know when sessionui is created
        self.onUiReady.connect(self._ui_ready)

    def _ui_ready(self):
        # session ui is available via self.session_ui now
        # if u requested memory to create in sessionui then
        # it is available via self.session_ui.memory and so on
        print('ui ready')

    @property
    def session_ui_sections(self):
        # what sections we want in session_ui
        return ['hooks', 'threads', 'registers', 'memory', 'console', 'watchers', 'javaexplorer']

    @property
    def session_type(self):
        """ return session name to show in menus etc
        """
        return 'Android'

    @property
    def main_menu(self):
        """ return our created menu
        """
        return self._menu

    def initialize(self, config):
        # session supports load/save then use config

        if not self.adb.available:
            self.onStopped.emit()
            return

        # setup ui etc for android
        self._setup_menu()
        # all fine were done wait for ui_ready
        self.onCreated.emit()

    def _setup_menu(self):
        """ Build Menus
        """
        # additional menus
        file_menu = QMenu('&Device')
        save_apk = QAction("&Save APK", self)
        save_apk.triggered.connect(self.save_apk)
        decompile_apk = QAction("&Decompile APK", self)
        decompile_apk.triggered.connect(self.decompile_apk)

        file_menu.addAction(save_apk)
        file_menu.addAction(decompile_apk)

        self._menu.append(file_menu)

        # additional menus
        #device_menu = QMenu('&Device')
        # self._menu.append(device_menu)

    def stop_session(self):
        # cleanup ur stuff

        # end session
        super().stop()

    def start(self, args):
        self.dwarf.onScriptDestroyed.connect(self.stop)
        if args.package is None:
            self._device_window.setModal(True)
            self._device_window.onSelectedProcess.connect(self.on_proc_selected)
            self._device_window.show()
        else:
            if not args.spawn:
                print('* Trying to attach to {0}'.format(args.package))
                ret_val = self.dwarf.attach(args.package, args.script)
                if ret_val == 2:
                    print('Failed to attach: use -sp to force spawn')
                    self.stop()
                    exit()
            else:
                print('* Trying to spawn {0}'.format(args.package))
                ret_val = self.dwarf.spawn(args.package, args.script)
                if ret_val != 0:
                    print('-failed-')
                    exit(ret_val)

    def decompile_apk(self):
        packages = self.adb.list_packages()
        if packages:
            accept, items = ListDialog.build_and_show(
                self.build_packages_list,
                packages,
                double_click_to_accept=True)
            if accept:
                if len(items) > 0:
                    path = items[0].get_apk_path()
                    AndroidDecompileUtil.decompile(self.adb, path)

    def save_apk(self):
        apk_dlg = ApkListDialog(self._app_window)
        apk_dlg.onApkSelected.connect(self._save_package)
        apk_dlg.show()

    def _save_package(self, data):
        package, path = data
        if path is not None:
            result = QFileDialog.getSaveFileName(caption='Location to save ' + package, directory='./' + package + '.apk', filter='*.apk')
            if result and result[0]:
                self.adb.pull(path, result[0])

    def on_proc_selected(self, pid):
        if pid:
            self.dwarf.attach(pid)
