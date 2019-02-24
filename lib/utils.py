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
import os
import subprocess
import sys

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QPixmap, QFont
from PyQt5.QtWidgets import QMessageBox

VERSION = sys.version_info

def do_shell_command(cmd, timeout=60):
    """ Execute cmd
    """
    try:
        # capture output is only supported in py 3.7
        if VERSION.minor >= 7:
            result = subprocess.run(cmd.split(' '), timeout=timeout, capture_output=True)
        else:
            result = subprocess.run(
                cmd.split(' '),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=timeout
            )

        if result.stderr:
            return result.stderr.decode('utf8')

        return result.stdout.decode('utf8')

    except subprocess.TimeoutExpired:
        return None  # todo: timeout doesnt mean cmd failed


def get_app_icon():
    """ Returns Icon (QPixmap)
    """
    return QPixmap(resource_path('assets/dwarf.png')).scaledToHeight(75, Qt.SmoothTransformation)


def parse_ptr(ptr):
    """ ptr parsing
    """
    if isinstance(ptr, str):
        if ptr.startswith('#'):
            ptr = ptr[1:]
        if ptr.startswith('0x'):
            ptr = int(ptr, 16)
        else:
            try:
                ptr = int(ptr)
            except ValueError:
                ptr = 0
    if not isinstance(ptr, int):
        ptr = 0
    return ptr


def resource_path(relative_path):
    """get path to resource
    """
    base_path = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
    # its /lib/ now so move one up os.pardir
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(base_path, relative_path)
    else:
        return os.path.join(base_path, os.pardir, relative_path)


def show_message_box(text, details=None):
    """ Shows a MessageBox
    """
    msg = QMessageBox()
    msg.setIconPixmap(get_app_icon())

    msg.setText(text)
    if details:
        msg.setDetailedText(details)
    msg.setStandardButtons(QMessageBox.Ok)
    msg.exec_()

def get_os_monospace_font():
    """ Get MonospaceFont for OS
    """
    platform = sys.platform

    if 'linux' in platform:
        return QFont('Monospace', 10)
    elif 'darwin' in platform:
        return QFont('Monaco', 12)
    elif 'freebsd' in platform:
        return QFont('Bitstream Vera Sans Mono', 10)
    else:
        # windows
        return QFont('Courier', 10) # Consolas ??

    #return QFontDatabase.systemFont(QFontDatabase.FixedFont) ??
