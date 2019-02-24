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
from PyQt5.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QPushButton, \
    QFileDialog, QSpinBox, QLabel, QWidget, QPlainTextEdit, QCompleter
from PyQt5.QtGui import QFont, QSyntaxHighlighter, QTextCharFormat, QColor, QFontDatabase, QPainter, QTextCursor
from PyQt5.QtCore import QFile, QRegExp, Qt, QRegularExpression, QRect, QSize, QStringListModel, pyqtSignal

from lib.utils import get_os_monospace_font
from lib.prefs import Prefs
from ui.dialog_scripts import ScriptsDialog


class DwarfCompleter(QCompleter):
    insertText = pyqtSignal(str)

    def __init__(self, myKeywords=None, parent=None):
        myKeywords = [
            'api.findExport(', 'api.addWatcher(', 'console', 'console.log(',
            'log', 'addWatcher', 'deleteHook', 'enumerateJavaClasses',
            'enumerateJavaMethods', 'findExport', 'getAddressTs',
            'hookAllJavaMethods', 'hookJava', 'hookNative'
            'hookOnLoad', 'javaBacktrace', 'isAddressWatched',
            'nativeBacktrace', 'release', 'removeWatcher', 'restart',
            'setData', 'startNativeTracer', 'stopNativeTracer'
        ]
        QCompleter.__init__(self, myKeywords, parent)
        self.setCompletionMode(QCompleter.PopupCompletion)
        self.highlighted.connect(self.setHighlighted)

    def setHighlighted(self, text):
        self.lastSelected = text

    def getSelected(self):
        return self.lastSelected


class JsHighlighter(QSyntaxHighlighter):
    def __init__(self, parent=None):
        super(JsHighlighter, self).__init__(parent)

        keyword_color = QColor('#C678DD')
        comment_color = QColor('#5C6370')
        function_color = QColor('#61AFEF')
        string_color = QColor('#98C379')
        number_color = QColor('#e06c75')
        constant_color = QColor('#D19A66')

        keywordFormat = QTextCharFormat()
        keywordFormat.setForeground(keyword_color)
        keywordFormat.setFontWeight(QFont.Bold)

        keywordPatterns = [
            "\\bbreak\\b", "\\bcase\\b", "\\bcatch\\b", "\\bclass\\b",
            "\\bconst\\b", "\\continue\\b", "\\bdebugger\\b", "\\bdefault\\b",
            "\\bdelete\\b", "\\bdo\\b", "\\belse\\b", "\\bexport\\b",
            "\\bextends\\b", "\\bfinally\\b", "\\bfor\\b", "\\bfunction\\b",
            "\\bif\\b", "\\bimport\\b", "\\bin\\b", "\\binstanceof\\b",
            "\\bnew\\b", "\\breturn\\b", "\\bsuper\\b", "\\bswitch\\b",
            "\\bthis\\b", "\\bthrow\\b", "\\btry\\b", "\\btypeof\\b",
            "\\bvar\\b", "\\bvoid\\b", "\\bwhile\\b", "\\bwith\\b",
            "\\byield\\b"
        ]

        self.highlightingRules = [(QRegExp(pattern), keywordFormat)
                                  for pattern in keywordPatterns]

        classFormat = QTextCharFormat()
        classFormat.setFontWeight(QFont.Bold)
        classFormat.setForeground(Qt.darkMagenta)
        self.highlightingRules.append((QRegExp("\\bnew [A-Za-z]+\\b"),
                                       classFormat))

        singleLineCommentFormat = QTextCharFormat()
        singleLineCommentFormat.setForeground(comment_color)
        singleLineCommentFormat.setFontItalic(True)
        self.highlightingRules.append((QRegExp("//[^\n]*"),
                                       singleLineCommentFormat))

        self.multiLineCommentFormat = QTextCharFormat()
        self.multiLineCommentFormat.setFontItalic(True)
        self.multiLineCommentFormat.setForeground(comment_color)

        numberFormat = QTextCharFormat()
        numberFormat.setForeground(number_color)
        self.highlightingRules.append((QRegExp("\-*\d+\\b"), numberFormat))

        quotationFormat = QTextCharFormat()
        quotationFormat.setForeground(string_color)
        self.highlightingRules.append((QRegExp("\".*\""), quotationFormat))
        self.highlightingRules.append((QRegExp("\'.*\'"), quotationFormat))

        functionFormat = QTextCharFormat()
        functionFormat.setForeground(function_color)
        self.highlightingRules.append(
            (QRegExp("(?!function)\\b[A-Za-z0-9_]+(?=\\()"), functionFormat))

        self.commentStartExpression = QRegExp("/\\*")
        self.commentEndExpression = QRegExp("\\*/")

    def highlightBlock(self, text):
        # todo: step trough text
        # todo: regexp suxx

        for pattern, format in self.highlightingRules:
            expression = QRegExp(pattern)
            expression.setMinimal(True)
            index = expression.indexIn(text)
            while index >= 0:
                length = expression.matchedLength()
                self.setFormat(index, length, format)
                index = expression.indexIn(text, index + length)

        self.setCurrentBlockState(0)

        startIndex = 0
        if self.previousBlockState() != 1:
            startIndex = self.commentStartExpression.indexIn(text)

        while startIndex >= 0:
            endIndex = self.commentEndExpression.indexIn(text, startIndex)

            if endIndex == -1:
                self.setCurrentBlockState(1)
                commentLength = len(text) - startIndex
            else:
                commentLength = endIndex - startIndex + self.commentEndExpression.matchedLength(
                )

            self.setFormat(startIndex, commentLength,
                           self.multiLineCommentFormat)
            startIndex = self.commentStartExpression.indexIn(
                text, startIndex + commentLength)


class JsCodeEditLineNums(QWidget):
    # todo: allow styling
    def __init__(self, parent=None):
        super(JsCodeEditLineNums, self).__init__(parent)
        self.editor = parent

    def sizeHint(self, event):
        return QSize(self.editor.calculated_linenum_width(), 0)

    def paintEvent(self, event):
        self.editor.draw_line_numbers(event)


class JsCodeEditor(QPlainTextEdit):
    # todo: linehighlight
    def __init__(self, parent=None):
        super(JsCodeEditor, self).__init__(parent)

        self.setFont(get_os_monospace_font())

        self._show_linenums = False

        if self._show_linenums:
            self.ui_line_numbers = JsCodeEditLineNums(self)
            self.blockCountChanged.connect(self.update_linenum_width)
            self.updateRequest.connect(self.update_line_numbers)
            self.update_linenum_width(0)

        self.setAutoFillBackground(True)
        # default distance is 80
        self.setTabStopDistance(self.fontMetrics().width('9999'))

        self.highlighter = JsHighlighter(self.document())

        # code completion
        self.completer = DwarfCompleter()
        self.completer.setWidget(self)
        self.completer.setCompletionMode(QCompleter.PopupCompletion)
        self.completer.setCaseSensitivity(Qt.CaseInsensitive)
        self.completer.insertText.connect(self.insertCompletion)

    @property
    def line_numbers(self):
        return self._show_linenums

    @line_numbers.setter
    def line_numbers(self, value):
        self._show_linenums = value
        self.ui_line_numbers = JsCodeEditLineNums(self)
        self.blockCountChanged.connect(self.update_linenum_width)
        self.updateRequest.connect(self.update_line_numbers)
        self.update_linenum_width(0)

    def update_linenum_width(self, count):
        self.setViewportMargins(self.calculated_linenum_width() + 10, 0, 0, 0)

    def update_line_numbers(self, rect, y):
        if y:
            self.ui_line_numbers.scroll(0, y)
        else:
            self.ui_line_numbers.update(0, rect.y(),
                                        self.ui_line_numbers.width(),
                                        rect.height())

        if rect.contains(self.viewport().rect()):
            self.update_linenum_width(0)

    def calculated_linenum_width(self):
        _char_width = self.fontMetrics().width("9")
        digits = 0
        m = max(1, self.blockCount())
        while m >= 10:
            m /= 10
            digits += 1

        # min_width + width * digits
        _width = 10 + _char_width * digits
        return _width + 10

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if self._show_linenums:
            bounds = self.contentsRect()
            new_bounds = QRect(bounds.left(), bounds.top(),
                               self.calculated_linenum_width(),
                               bounds.height())
            self.ui_line_numbers.setGeometry(new_bounds)

    def draw_line_numbers(self, event):
        painter = QPainter(self.ui_line_numbers)
        # background
        painter.fillRect(event.rect(), Qt.transparent)

        # linenums
        current_block = self.firstVisibleBlock()
        block_num = current_block.blockNumber()

        top = self.blockBoundingGeometry(current_block).translated(
            self.contentOffset()).top()
        bottom = top + self.blockBoundingRect(current_block).height()

        while current_block.isValid() and (top <= event.rect().bottom()):
            if current_block.isVisible() and (bottom >= event.rect().top()):
                s = ("{0}".format(block_num + 1))
                painter.setPen(QColor('#636d83'))
                painter.setFont(self.font())
                painter.drawText(0, top,
                                 self.calculated_linenum_width() - 5,
                                 self.fontMetrics().height(),
                                 Qt.AlignRight | Qt.AlignVCenter, s)

            current_block = current_block.next()
            top = bottom
            bottom = top + self.blockBoundingRect(current_block).height()
            block_num += 1

    def focusInEvent(self, event):
        if self.completer:
            self.completer.setWidget(self)
        super().focusInEvent(event)

    def keyPressEvent(self, event):

        tc = self.textCursor()
        if event.key() == Qt.Key_Enter or event.key(
        ) == Qt.Key_Return or event.key() == Qt.Key_Tab:
            if self.completer.popup().isVisible():
                self.completer.insertText.emit(self.completer.getSelected())
                self.completer.setCompletionMode(QCompleter.PopupCompletion)
                event.ignore()
                return

        super().keyPressEvent(event)

        tc.select(QTextCursor.WordUnderCursor)
        cr = self.cursorRect()

        if len(tc.selectedText()) > 0:
            self.completer.setCompletionPrefix(tc.selectedText())
            popup = self.completer.popup()
            popup.setCurrentIndex(self.completer.completionModel().index(0, 0))

            cr.setWidth(
                self.completer.popup().sizeHintForColumn(0) +
                self.completer.popup().verticalScrollBar().sizeHint().width())
            self.completer.complete(cr)
        else:
            self.completer.popup().hide()

        return
        if self.completer and self.completer.popup() and self.completer.popup(
        ).isVisible():
            if event.key() in (Qt.Key_Enter, Qt.Key_Return, Qt.Key_Escape,
                               Qt.Key_Tab, Qt.Key_Backtab):
                event.ignore()
                return
            # return super().keyPressEvent(event)

        isShortcut = (event.modifiers() == Qt.ControlModifier
                      and event.key() == Qt.Key_Space)
        if (not self.completer or not isShortcut):
            super().keyPressEvent(event)

        ctrlOrShift = event.modifiers() in (Qt.ControlModifier,
                                            Qt.ShiftModifier)
        if ctrlOrShift and event.text() == '':
            return

        eow = "~!@#$%^&*+{}|:\"<>?,./;'[]\\-="  # end of word

        hasModifier = ((event.modifiers() != Qt.NoModifier)
                       and not ctrlOrShift)

        completionPrefix = self.textUnderCursor()

        if not isShortcut:
            if self.completer.popup():
                self.completer.popup().hide()
            return

        self.completer.setCompletionPrefix(completionPrefix)
        popup = self.completer.popup()
        popup.setCurrentIndex(self.completer.completionModel().index(0, 0))
        cr = self.cursorRect()
        cr.setWidth(self.completer.popup().sizeHintForColumn(
            0) + self.completer.popup().verticalScrollBar().sizeHint().width())
        self.completer.complete(cr)

    def insertCompletion(self, completion):
        tc = self.textCursor()
        extra = (len(completion) - len(self.completer.completionPrefix()))
        tc.movePosition(QTextCursor.Left)
        tc.movePosition(QTextCursor.EndOfWord)
        tc.insertText(completion[-extra:])
        self.setTextCursor(tc)
        self.completer.popup().hide()

    def textUnderCursor(self):
        tc = self.textCursor()
        tc.select(QTextCursor.WordUnderCursor)
        return tc.selectedText()
