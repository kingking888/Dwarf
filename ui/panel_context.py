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
import json
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QStandardItemModel, QStandardItem, QColor
from PyQt5.QtWidgets import QHeaderView, QTabWidget

from ui.widget_item_not_editable import NotEditableTableWidgetItem
from ui.widget_memory_address import MemoryAddressWidget
from ui.widget_native_register import NativeRegisterWidget
from ui.widget_table_base import TableBaseWidget

from ui.list_view import DwarfListView


class ContextPanel(QTabWidget):

    CONTEXT_TYPE_NATIVE = 0
    CONTEXT_TYPE_JAVA = 1
    CONTEXT_TYPE_EMULATOR = 2

    def __init__(self, parent=None):
        super(ContextPanel, self).__init__(parent=parent)

        self._app_window = parent

        self._nativectx_model = QStandardItemModel(0, 4)
        self._nativectx_model.setHeaderData(0, Qt.Horizontal, 'Reg')
        self._nativectx_model.setHeaderData(0, Qt.Horizontal, Qt.AlignCenter, Qt.TextAlignmentRole)
        self._nativectx_model.setHeaderData(1, Qt.Horizontal, 'Value')
        #self._nativectx_model.setHeaderData(1, Qt.Horizontal, Qt.AlignCenter, Qt.TextAlignmentRole)
        self._nativectx_model.setHeaderData(2, Qt.Horizontal, 'Decimal')
        #self._nativectx_model.setHeaderData(2, Qt.Horizontal, Qt.AlignCenter, Qt.TextAlignmentRole)
        self._nativectx_model.setHeaderData(3, Qt.Horizontal, 'Telescope')

        self._nativectx_list = DwarfListView()
        self._nativectx_list.setModel(self._nativectx_model)

        self._nativectx_list.header().setSectionResizeMode(
            0, QHeaderView.ResizeToContents)
        self._nativectx_list.header().setSectionResizeMode(
            1, QHeaderView.ResizeToContents)
        self._nativectx_list.header().setSectionResizeMode(
            2, QHeaderView.ResizeToContents)

        self._emulatorctx_model = QStandardItemModel(0, 3)
        self._emulatorctx_model.setHeaderData(0, Qt.Horizontal, 'Reg')
        self._emulatorctx_model.setHeaderData(0, Qt.Horizontal, Qt.AlignCenter, Qt.TextAlignmentRole)
        self._emulatorctx_model.setHeaderData(1, Qt.Horizontal, 'Value')
        #self._emulatorctx_model.setHeaderData(1, Qt.Horizontal, Qt.AlignCenter, Qt.TextAlignmentRole)
        self._emulatorctx_model.setHeaderData(2, Qt.Horizontal, 'Decimal')

        self._emulatorctx_list = DwarfListView()
        self._emulatorctx_list.setModel(self._emulatorctx_model)

        self._emulatorctx_list.header().setSectionResizeMode(
            0, QHeaderView.ResizeToContents)
        self._emulatorctx_list.header().setSectionResizeMode(
            1, QHeaderView.ResizeToContents)

        self._javactx_model = QStandardItemModel(0, 3)
        self._javactx_model.setHeaderData(0, Qt.Horizontal, 'Argument')
        self._javactx_model.setHeaderData(0, Qt.Horizontal, Qt.AlignCenter, Qt.TextAlignmentRole)
        self._javactx_model.setHeaderData(1, Qt.Horizontal, 'Class')
        #self._javactx_model.setHeaderData(1, Qt.Horizontal, Qt.AlignCenter, Qt.TextAlignmentRole)
        self._javactx_model.setHeaderData(2, Qt.Horizontal, 'Value')

        self._javactx_list = DwarfListView()
        self._javactx_list.setModel(self._javactx_model)

        self._javactx_list.header().setSectionResizeMode(
            0, QHeaderView.ResizeToContents)
        self._javactx_list.header().setSectionResizeMode(
            1, QHeaderView.ResizeToContents)
        self._javactx_list.header().setSectionResizeMode(
            2, QHeaderView.ResizeToContents)

    # ************************************************************************
    # **************************** Functions *********************************
    # ************************************************************************

    def clear(self):
        self._nativectx_list.clear()
        self._emulatorctx_list.clear()
        self._javactx_list.clear()

    def set_context(self, ptr, context_type, context):
        self.clear()
        if isinstance(context, str):
            context = json.loads(context)

        if context_type == ContextPanel.CONTEXT_TYPE_NATIVE:
            self._set_native_context(ptr, context)
        elif context_type == ContextPanel.CONTEXT_TYPE_JAVA:
            self._set_java_context(ptr, context)
        elif context_type == ContextPanel.CONTEXT_TYPE_EMULATOR:
            self._set_emulator_context(ptr, context)
        else:
            raise Exception('unknown context type')

    def have_context(self):
        return self.count() > 0

    def show_context_tab(self, tab_name):
        index = 0
        tab_name = tab_name.join(tab_name.split()).lower()
        if tab_name == 'native':
            index = self.indexOf(self._nativectx_list)
        elif tab_name == 'emulator':
            index = self.indexOf(self._emulatorctx_list)
        elif tab_name == 'java':
            index = self.indexOf(self._javactx_list)

        if self.count() > 0:
            self.setCurrentIndex(index)

    def _set_native_context(self, ptr, context):
        if self.indexOf(self._nativectx_list) == -1:
            self.addTab(self._nativectx_list, 'Native')
            self.show_context_tab('Native')
        else:
            self.show_context_tab('Native')

        context_ptr = ptr

        for register in sorted(context):
            # todo: ???
            if register.lower() == 'tojson':
                continue

            reg_name = QStandardItem()
            reg_name.setTextAlignment(Qt.AlignCenter)
            reg_name.setForeground(Qt.red)
            value_x = QStandardItem()
            # value_x.setTextAlignment(Qt.AlignCenter)
            value_dec = QStandardItem()
            # value_dec.setTextAlignment(Qt.AlignCenter)
            telescope = QStandardItem()

            reg_name.setText(register)
            reg_name.setData(context_ptr)

            if context[register] is not None:
                str_fmt = '0x{0:x}'
                if self._nativectx_list.uppercase_hex:
                    str_fmt = '0x{0:X}'

                value_x.setText(str_fmt.format(int(context[register]['value'], 16)))

                value_dec.setText('{0:d}'.format(int(context[register]['value'], 16)))

                if context[register]['isValidPointer']:
                    if 'telescope' in context[register] and context[register]['telescope'] is not None:
                        telescope = QStandardItem()
                        telescope.setText(str(context[register]['telescope'][1]))
                        if context[register]['telescope'][0] == 1:
                            telescope.setData('isAddress')

                        if context[register]['telescope'][0] == 0:
                            telescope.setForeground(Qt.darkGreen)
                        elif context[register]['telescope'][0] == 2:
                            telescope.setForeground(Qt.white)
                        elif context[register]['telescope'][0] != 1:
                            telescope.setForeground(Qt.darkGray)

            self._nativectx_model.appendRow([reg_name, value_x, value_dec, telescope])

    def _set_emulator_context(self, ptr, context):
        if self.indexOf(self._emulatorctx_list) == -1:
            self.addTab(self._emulatorctx_list, 'Emulator')
            self.show_context_tab('Emulator')
        else:
            self.show_context_tab('Emulator')

        context_ptr = ptr

        context = context.__dict__

        for register in sorted(context):
            # todo: ???
            if register.startswith('_'):
                continue

            reg_name = QStandardItem()
            reg_name.setTextAlignment(Qt.AlignCenter)
            reg_name.setForeground(QColor('#39c'))
            value_x = QStandardItem()
            # value_x.setTextAlignment(Qt.AlignCenter)
            value_dec = QStandardItem()
            # value_dec.setTextAlignment(Qt.AlignCenter)
            telescope = QStandardItem()

            reg_name.setText(register)
            reg_name.setData(context_ptr)

            if context[register] is not None:
                if isinstance(context[register], int):
                    str_fmt = '0x{0:x}'
                    if self._emulatorctx_list.uppercase_hex:
                        str_fmt = '0x{0:X}'

                    value_x.setText(str_fmt.format(context[register]))

                    value_dec.setText('{0:d}'.format(context[register]))

            self._emulatorctx_model.appendRow([reg_name, value_x, value_dec])

    # ************************************************************************
    # **************************** Handlers **********************************
    # ************************************************************************


"""
class ContextPanel(TableBaseWidget):
    CONTEXT_TYPE_NATIVE = 0
    CONTEXT_TYPE_JAVA = 1
    CONTEXT_TYPE_EMULATOR = 2

    def __init__(self, app, *__args):
        super().__init__(app, *__args)
        self.context_ptr = ''
        self.is_java_context = False

    def item_double_clicked(self, item):
        if isinstance(item, NativeRegisterWidget) and item.is_valid_ptr():
            self.app.get_memory_panel().read_memory(item.value)
        elif isinstance(item, MemoryAddressWidget):
            self.app.get_memory_panel().read_memory(item.get_address())
        elif self.is_java_context:
            self.on_menu_action('expand', item)

        # return false and manage double click here
        return False

    def set_menu_actions(self, item, menu):
        if self.is_java_context:
            if item is not None:
                action_expand = menu.addAction("Explorer")
                action_expand.setData('expand')

    def on_menu_action(self, action_data, item):
        if action_data == 'expand':
            self.app.get_java_explorer_panel().set_handle_arg(item.row())
            return False
        return True

    def __initialize_context(self):
        self.setRowCount(0)
        self.setColumnCount(0)

    def __set_emulator_context(self, ptr, context):
        self.__initialize_context()
        self.context_ptr = ptr
        self.is_java_context = False
        self.setColumnCount(3)
        self.setHorizontalHeaderLabels(['reg', 'value', 'decimal'])
        for reg in sorted(context.__dict__):
            if reg.startswith('_'):
                continue

            i = self.rowCount()
            self.insertRow(i)

            q = NotEditableTableWidgetItem(reg)
            q.setForeground(Qt.gray)
            self.setItem(i, 0, q)
            q = NotEditableTableWidgetItem(reg)
            q.setFlags(Qt.NoItemFlags)
            q.setForeground(Qt.gray)
            self.setItem(i, 0, q)

            q = NativeRegisterWidget(reg, {
                'value': hex(context.__dict__[reg]),
                'isValidPointer': False  # @todo!
            })
            self.setItem(i, 1, q)

            q = NotEditableTableWidgetItem(str(context.__dict__[reg]))
            q.setForeground(Qt.darkCyan)
            self.setItem(i, 2, q)
        self.resizeRowsToContents()
        self.horizontalHeader().setStretchLastSection(True)

    def __set_java_context(self, ptr, context):
        self.__initialize_context()
        self.context_ptr = ptr
        self.is_java_context = True
        self.setColumnCount(3)
        self.setHorizontalHeaderLabels(['argument', 'class', 'value'])
        for arg in context:
            i = self.rowCount()
            self.insertRow(i)

            q = NotEditableTableWidgetItem(arg)
            q.setForeground(Qt.gray)
            self.setItem(i, 0, q)

            q = NotEditableTableWidgetItem(context[arg]['className'])
            if isinstance(context[arg]['handle'], str):
                q.setFlags(Qt.NoItemFlags)
                q.setForeground(Qt.lightGray)
                self.item(i, 0).setFlags(Qt.NoItemFlags)
                self.item(i, 0).setForeground(Qt.lightGray)
            self.setItem(i, 1, q)

            if context[arg] is not None:
                q = QTableWidgetItem('null')
                q.setForeground(Qt.gray)
                q.setForeground(Qt.gray)
                self.setItem(i, 2, q)
        self.resizeRowsToContents()
        self.horizontalHeader().setStretchLastSection(True)

    def __set_native_context(self, ptr, context):
        self.__initialize_context()
        self.context_ptr = ptr
        self.is_java_context = False
        self.setColumnCount(4)
        self.setHorizontalHeaderLabels(['reg', 'value', 'decimal', 'telescope'])

        #if self.app.get_dwarf().get_loading_library() is not None:
        #    self.context_ptr = self.app.get_dwarf().get_loading_library()

        for reg in context:
            if reg.lower() == 'tojson':
                continue

            i = self.rowCount()
            self.insertRow(i)

            q = NotEditableTableWidgetItem(reg)
            q.setFlags(Qt.NoItemFlags)
            q.setForeground(Qt.gray)
            self.setItem(i, 0, q)

            if context[reg] is not None:
                q = NativeRegisterWidget(reg, context[reg])

                self.setItem(i, 1, q)

                q = NotEditableTableWidgetItem(str(int(context[reg]['value'], 16)))
                q.setForeground(Qt.darkCyan)
                self.setItem(i, 2, q)

                if context[reg]['isValidPointer']:
                    ts = context[reg]['telescope']
                    if ts is not None:
                        if ts[0] == 1:
                            q = MemoryAddressWidget(str(ts[1]))
                        else:
                            q = NotEditableTableWidgetItem(str(ts[1]))
                            q.setFlags(Qt.NoItemFlags)

                        if ts[0] == 0:
                            q.setForeground(Qt.darkGreen)
                        elif ts[0] == 2:
                            q.setForeground(Qt.white)
                        elif ts[0] != 1:
                            q.setForeground(Qt.darkGray)

                        self.setItem(i, 3, q)
        self.resizeRowsToContents()
        self.horizontalHeader().setStretchLastSection(True)

    def set_context(self, ptr, context_type, context):
        if context_type == ContextPanel.CONTEXT_TYPE_NATIVE:
            self.__set_native_context(ptr, context)
        elif context_type == ContextPanel.CONTEXT_TYPE_JAVA:
            self.__set_java_context(ptr, context)
        elif context_type == ContextPanel.CONTEXT_TYPE_EMULATOR:
            self.__set_emulator_context(ptr, context)
        else:
            raise Exception('unknown context type')

    def have_context(self):
        return self.rowCount() > 0
"""
