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
from PyQt5.QtGui import QStandardItem, QStandardItemModel
from PyQt5.QtWidgets import QTreeView, QHeaderView, QMenu

from ui.list_view import DwarfListView


class ContextsListPanel(DwarfListView):

    onItemDoubleClicked = pyqtSignal(dict, name='onItemDoubleClicked')

    def __init__(self, parent=None):
        super(ContextsListPanel, self).__init__(parent=parent)
        self.dwarf = parent.dwarf

        self.threads_model = QStandardItemModel(0, 3)
        self.threads_model.setHeaderData(0, Qt.Horizontal, 'TID')
        self.threads_model.setHeaderData(0, Qt.Horizontal, Qt.AlignCenter,
                                         Qt.TextAlignmentRole)
        self.threads_model.setHeaderData(1, Qt.Horizontal, 'PC')
        self.threads_model.setHeaderData(1, Qt.Horizontal, Qt.AlignCenter,
                                         Qt.TextAlignmentRole)
        self.threads_model.setHeaderData(2, Qt.Horizontal, 'Symbol')

        self.setModel(self.threads_model)
        self.header().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.header().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.header().setSectionResizeMode(2, QHeaderView.ResizeToContents)

        self.doubleClicked.connect(self._item_doubleclicked)

    def add_context(self, data, library_onload=None):
        is_java = data['is_java']
        tid = QStandardItem()
        tid.setText(str(data['tid']))
        tid.setData(data, Qt.UserRole + 1)
        tid.setTextAlignment(Qt.AlignCenter)

        pc_col = QStandardItem()
        if not is_java:
            pc = int(data['ptr'], 16)
            if 'arm' in self.dwarf.arch:
                # dethumbify
                if pc & 1 == 1:
                    pc -= 1

            str_fmt = '0x{0:X}'
            if self._uppercase_hex:
                str_fmt = '0x{0:X}'
            else:
                str_fmt = '0x{0:x}'

            pc_col.setText(str_fmt.format(pc))
        else:
            parts = data['ptr'].split('.')
            pc_col.setText(parts[len(parts) - 1])

        symb_col = QStandardItem()
        if library_onload is None:
            if not is_java:
                str_fmt = ('{0} - {1}'.format(data['context']['pc']['symbol']['moduleName'], data['context']['pc']['symbol']['name']))
                symb_col.setText(str_fmt)
            else:
                symb_col.setText('.'.join(parts[:len(parts) - 1]))
        else:
            str_fmt = ('loading {0}'.format(library_onload))
            symb_col.setText(str_fmt)

        self.threads_model.appendRow([tid, pc_col, symb_col])

    def resume_tid(self, tid):
        # todo: check why removing here and removing in on_proc_resume
        for i in range(self.threads_model.rowCount()):
            is_tid = self.threads_model.item(i, 0).text()
            if is_tid == str(tid):
                self.threads_model.removeRow(i)

    def _item_doubleclicked(self, model_index):
        row = self.threads_model.itemFromIndex(model_index).row()
        if row != -1:
            context_data = self.threads_model.item(row, 0).data(Qt.UserRole + 1)
            self.onItemDoubleClicked.emit(context_data)

    #self.dwarf_api('release', tid)


"""
class ContextsListPanel(TableBaseWidget):
    def __init__(self, app, *__args):
        super().__init__(app, 0, 0)
        

    def set_menu_actions(self, item, menu):
        if item is not None:
            ctx = self.item(item.row(), 0)
            if isinstance(ctx, ContextItem):
                emulator = menu.addAction('Emulator')
                if self.app.get_emulator_panel() is not None:
                    emulator.setEnabled(False)
                else:
                    emulator.setData('emulator')
                if self.app.get_dwarf().get_native_traced_tid() > 0:
                    trace = menu.addAction("Stop trace")
                else:
                    trace = menu.addAction("Trace")
                trace.setData('trace')
                menu.addSeparator()
                resume = menu.addAction("Resume")
                resume.setData('resume')

    def on_menu_action(self, action_data, item):
        ctx = self.item(item.row(), 0)
        if isinstance(ctx, ContextItem):
            if action_data == 'emulator':
                self.app.get_session_ui().add_dwarf_tab(SessionUi.TAB_EMULATOR, request_focus=True)
            elif action_data == 'trace':
                if self.app.get_dwarf().get_native_traced_tid() > 0:
                    self.app.get_dwarf().native_tracer_stop()
                else:
                    tid = ctx.get_tid()
                    self.app.get_dwarf().native_tracer_start(tid)
            elif action_data == 'resume':
                self.app.resume(ctx.get_tid())
                return False

    def resume_tid(self, tid):
        items = self.findItems(str(tid), Qt.MatchExactly)
        if len(items) > 0:
            self.removeRow(items[0].row())

    def add_context(self, data, library_onload=None):
        if self.columnCount() == 0:
            self.setColumnCount(3)
            self.setHorizontalHeaderLabels(['tid', 'pc', 'symbol'])

        is_java = data['is_java']

        row = self.rowCount()
        self.insertRow(row)
        q = ContextItem(data, str(data['tid']))
        q.setForeground(Qt.darkCyan)
        self.setItem(row, 0, q)

        if not is_java:
            pc = int(data['ptr'], 16)
            # dethumbify
            if pc & 1 == 1:
                pc -= 1
            q = MemoryAddressWidget(hex(pc))
        else:
            parts = data['ptr'].split('.')
            q = NotEditableTableWidgetItem(parts[len(parts) - 1])
            q.setForeground(Qt.red)
            q.setFlags(Qt.NoItemFlags)
        self.setItem(row, 1, q)

        if library_onload is None:
            if not is_java:
                q = NotEditableTableWidgetItem('%s - %s' % (
                    data['context']['pc']['symbol']['moduleName'], data['context']['pc']['symbol']['name']))
            else:
                q = NotEditableTableWidgetItem('.'.join(parts[:len(parts) - 1]))
        else:
            q = NotEditableTableWidgetItem('loading %s' % library_onload)

        q.setFlags(Qt.NoItemFlags)
        q.setForeground(Qt.gray)
        self.setItem(row, 2, q)
        self.resizeRowsToContents()
        self.horizontalHeader().setStretchLastSection(True)

    def item_double_clicked(self, item):
        if isinstance(item, ContextItem):
            self.app.apply_context(item.get_context())
            return False
        return True

    def clear(self):
        self.setRowCount(0)
        self.setColumnCount(0)
        self.resizeColumnsToContents()
        self.horizontalHeader().setStretchLastSection(True)
"""
