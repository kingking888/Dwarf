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
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QStandardItemModel, QIcon, QPixmap
from PyQt5.QtWidgets import (QListView, QWidget, QVBoxLayout, QHeaderView,
                             QHBoxLayout, QPushButton, QSpacerItem,
                             QSizePolicy, QMenu)

from lib import utils
import pyperclip


# todo: remove utils deps
class AddressListWidget(QWidget):
    onItemSelected = pyqtSignal(str, name='onItemSelected')
    onItemAddClick = pyqtSignal(name='onItemAddClick')
    onItemAdded = pyqtSignal(str, name='onItemAdded')
    onItemRemoved = pyqtSignal(str, name='onItemRemoved')

    @property
    def uppercase_hex(self):
        return self._uppercase_hex

    @uppercase_hex.setter
    def uppercase_hex(self, value):
        if isinstance(value, bool):
            self._uppercase_hex = value
        elif isinstance(value, str):
            self._uppercase_hex = (value == 'upper')

    def __init__(self, parent=None):
        super(AddressListWidget, self).__init__(parent=parent)
        self._app_window = parent
        # self.setContextMenuPolicy(Qt.ActionsContextMenu)
        # self.customContextMenuRequested.connect(self._on_contextmenu)

        self._uppercase_hex = True

        v_box = QVBoxLayout(self)
        v_box.setContentsMargins(0, 0, 0, 0)
        self.list_view = QListView(self)
        self.list_view.setAutoFillBackground(True)
        self.list_view.setAlternatingRowColors(True)
        self.list_view.setEditTriggers(self.list_view.NoEditTriggers)
        self.list_view.setModel(QStandardItemModel(0, 1, self))
        self.list_view.doubleClicked.connect(self._on_item_dblclick)
        self.list_view.setContextMenuPolicy(Qt.CustomContextMenu)
        self.list_view.customContextMenuRequested.connect(self._on_contextmenu)
        v_box.addWidget(self.list_view)
        header = QHeaderView(Qt.Horizontal, self)

        h_box = QHBoxLayout(header)
        h_box.setContentsMargins(0, 0, 0, 0)
        icon = QIcon()
        icon.addPixmap(QPixmap(utils.resource_path('assets/icons/plus.svg')))
        btn1 = QPushButton(icon, '')
        btn1.setFixedSize(20, 20)
        btn1.clicked.connect(self._on_additem_clicked)
        btn2 = QPushButton(
            QIcon(QPixmap(utils.resource_path('assets/icons/dash.svg'))), '')
        btn2.setFixedSize(20, 20)
        btn2.clicked.connect(self.delete_items)
        btn3 = QPushButton(
            QIcon(QPixmap(utils.resource_path('assets/icons/trashcan.svg'))),
            '')
        btn3.setFixedSize(20, 20)
        btn3.clicked.connect(self.clear_list)
        h_box.addWidget(btn1)
        h_box.addWidget(btn2)
        h_box.addSpacerItem(
            QSpacerItem(0, 0, QSizePolicy.Expanding, QSizePolicy.Preferred))
        h_box.addWidget(btn3)
        header.setLayout(h_box)
        header.setFixedHeight(25)
        v_box.addWidget(header)
        self.setLayout(v_box)

    def _on_contextmenu(self, pos):
        index = self.list_view.indexAt(pos)
        data = self.list_view.model().data(index)
        if data:
            self.list_view.setCurrentIndex(index)
            pt = self.list_view.mapToGlobal(pos)
            context_menu = QMenu(self)
            context_menu.addAction('Copy Address', self._copy_address)
            context_menu.addAction('Delete Address', self.delete_items)
            context_menu.exec_(pt)

    def add_address(self, ptr):
        if isinstance(ptr, str):
            ptr = utils.parse_ptr(ptr)

        model = self.list_view.model()
        model.insertRow(0)
        sf = ''
        if self._uppercase_hex:
            sf = '0x{0:X}'.format(ptr)
        else:
            sf = '0x{0:x}'.format(ptr)
        model.setData(model.index(0, 0), sf)

    def remove_address(self, ptr):
        if isinstance(ptr, str):
            ptr = utils.parse_ptr(ptr)

        sf = ''
        if self._uppercase_hex:
            sf = '0x{0:X}'.format(ptr)
        else:
            sf = '0x{0:x}'.format(ptr)

        model = self.list_view.model()
        for item in range(model.rowCount()):
            if sf == model.item(item).text():
                model.removeRow(item)

    def _copy_address(self):
        data = self.list_view.model().data(self.list_view.currentIndex())
        pyperclip.copy(data)

    def _on_item_dblclick(self, model_index):
        data = self.list_view.model().data(model_index)
        self.onItemSelected.emit(data)

    def _on_additem_clicked(self):
        self.onItemAddClick.emit()

    def delete_items(self):
        """ Delete selected Items
        """
        model = self.list_view.model()

        for selected_item in self.list_view.selectedIndexes():
            # tell were removing it
            ptr = model.data(selected_item)
            self.onItemRemoved.emit(ptr)
            # remove it
            # model.removeRow(selected_item.row())

    def clear_list(self):
        model = self.list_view.model()

        # go through all items and tell other it gets removed
        for item in range(model.rowCount()):
            ptr = model.item(item).text()
            self.onItemRemoved.emit(ptr)

        # delete entrys in list
        model.removeRows(0, model.rowCount())
