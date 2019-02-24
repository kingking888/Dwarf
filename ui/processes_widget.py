
import frida

from PyQt5.QtCore import *
from PyQt5.QtGui import QStandardItemModel
from PyQt5.QtWidgets import QWidget, QTreeView, QHeaderView


class ProcessesWidget(QTreeView):
    """ ProcessListWidget

        args:
            device needed

        Signals:
            onPIDSelected(pid)
    """

    onPIDSelected = pyqtSignal(int, name='onPIDSelected')

    def __init__(self, device, parent=None):
        super(ProcessesWidget, self).__init__(parent=parent)

        self.device = device

        self.setHeaderHidden(False)
        self.setRootIsDecorated(False)
        self.setAlternatingRowColors(True)
        self.setEditTriggers(self.NoEditTriggers)

        model = QStandardItemModel(0, 2, parent)
        model.setHeaderData(0, Qt.Horizontal, "PID")
        model.setHeaderData(1, Qt.Horizontal, "Name")

        self.doubleClicked.connect(self.on_item_clicked)

        self.setModel(model)

    def clear(self):
        self.model().removeRows(0, self.model().rowCount())
        #self.model = None

    def add_item(self, item):
        model = self.model()
        model.insertRow(0)
        model.setData(model.index(0, 0), item['pid'])
        model.setData(model.index(0, 1), item['name'])

    def on_item_clicked(self):
        model = self.model()

        index = self.selectionModel().currentIndex()
        sel_pid = model.itemData(model.index(index.row(), 0))

        if len(sel_pid) == 1:
            self.onPIDSelected.emit(int(sel_pid[0]))
