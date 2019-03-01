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
import binascii
import json
from threading import Thread

import frida
from PyQt5.QtCore import QObject, pyqtSignal
from PyQt5.QtWidgets import QFileDialog
from ui.hex_edit import HighLight, HighlightExistsError

from lib import utils
from lib.context import Context
from lib.emulator import Emulator
from lib.git import Git
from lib.hook import Hook
from lib.kernel import Kernel
from lib.prefs import Prefs
from lib.scripts_manager import ScriptsManager
from ui.dialog_input import InputDialog
from ui.panel_trace import TraceEvent
from ui.ui_session import SessionUi


class Dwarf(QObject):

    onScriptLoaded = pyqtSignal(name='onScriptLoaded')
    onScriptDestroyed = pyqtSignal(name='onScriptDestroyed')

    onAddNativeHook = pyqtSignal(Hook, name='onAddNativeHook')
    onAddJavaHook = pyqtSignal(Hook, name='onAddJavaHook')
    onAddOnLoadHook = pyqtSignal(Hook, name='onAddOnLoadHook')
    onApplyContext = pyqtSignal(dict, name='onApplyContext')

    # watcher
    onWatcherAdded = pyqtSignal(str, int, name='onWatcherAdded')
    onWatcherRemoved = pyqtSignal(str, name='onWatcherRemoved')

    # ranges
    onSetRanges = pyqtSignal(list, name='onSetRanges')
    # modules
    onSetModules = pyqtSignal(list, name='onSetModules')
    onHitOnLoad = pyqtSignal(list, name='onHitOnLoad')
    #
    onLogToConsole = pyqtSignal(str, name='onLogToConsole')
    onTraceData = pyqtSignal(str, name='onTraceData')
    onSetData = pyqtSignal(list, name='onSetData')
    onThreadResumed = pyqtSignal(int, name='onThreadResumed')

    onEnumerateJavaMethodsComplete = pyqtSignal(list, name='onEnumerateJavaMethodsComplete')

    onMemoryScanComplete = pyqtSignal(list, name='onMemoryScanComplete')
    onMemoryScanMatch = pyqtSignal(list, name='onMemoryScanMatch')

    def __init__(self, session=None, parent=None, device=None):
        super(Dwarf, self).__init__(parent=parent)

        self.app_window = parent

        self.java_available = False
        self.loading_library = False

        # frida device
        self.device = device

        # process
        self.pid = 0
        self.process = None
        self.script = None

        # kernel
        self.kernel = Kernel(self)

        # hooks
        self.hooks = {}
        self.on_loads = {}
        self.java_hooks = {}
        self.temporary_input = ''
        self.native_pending_args = None
        self.java_pending_args = None

        # context
        self.arch = ''
        self.pointer_size = 0
        self.contexts = {}
        self.context_tid = 0

        # tracers
        self.native_traced_tid = 0

        # core utils
        self.emulator = Emulator(self)
        self.git = Git()
        self.prefs = Prefs()
        self.script_manager = ScriptsManager(self)

        self._spawned = False

        self.onApplyContext.connect(self._on_apply_context)

        self.keystone_installed = False
        try:
            import keystone.keystone_const
            self.keystone_installed = True
        except:
            pass

    def _get_device(self):
        try:
            self.device = frida.get_usb_device()
        except frida.TimedOutError:
            self.device = None

        if self.device is None:
            # now check for a local device
            try:
                self.device = frida.get_local_device()
            except frida.TimedOutError:
                self.device = None

            if self.device is None:
                return 1
        return 0

    def _reinitialize(self):
        self.java_available = False
        self.loading_library = False

        # frida device
        self.device = None

        # process
        self._spawned = False
        self.pid = 0
        self.process = None
        self.script = None

        # hooks
        self.hooks = {}
        self.on_loads = {}
        self.java_hooks = {}
        self.temporary_input = ''
        self.native_pending_args = None
        self.java_pending_args = None

        # tracers
        self.native_traced_tid = 0

    def device_picked(self, device):
        self.device = device

    def attach(self, pid_or_package, script=None, print_debug_error=True):
        if self.device is None:
            # fallback to usb device
            # can come from -p in args
            err = self._get_device()
            if err > 0:
                return err

        if self.process is not None:
            self.detach()

        try:
            self.process = self.device.attach(pid_or_package)
            self.process.enable_jit()
            self.pid = self.process._impl.pid
            self._spawned = False
        except Exception as e:
            if print_debug_error:
                utils.show_message_box('Failed to attach to %s' % str(pid_or_package), str(e))
            return 2

        self.load_script(script)
        return 0

    def detach(self):
        if self.script is not None:
            self.dwarf_api('_detach')
            self.script.unload()
        if self.process is not None:
            self.process.detach()

    def load_script(self, script=None):
        with open('lib/script.js', 'r') as f:
            s = f.read()
        self.script = self.process.create_script(s)
        self.script.on('message', self.on_message)
        self.script.on('destroyed', self.on_destroyed)
        self.script.load()

        if script is not None:
            user_script = ''
            if os.path.exists(script):
                with open(script, 'r') as script_file:
                    user_script = script_file.read()

                self.dwarf_api('evaluateFunction', user_script)

        self.onScriptLoaded.emit()
        # self.app_window.on_script_loaded()

    def spawn(self, package, script=None):
        if self.device is None:
            # fallback to usb device
            # can come from -p in args
            err = self._get_device()
            if err > 0:
                return err

        if self.process is not None:
            self.detach()

        try:
            self.pid = self.device.spawn(package)
            self.process = self.device.attach(self.pid)
            self.process.enable_jit()
            self._spawned = True
        except Exception as e:
            utils.show_message_box('Failed to spawn to %s' % package, str(e))
            return 2
        self.load_script(script)
        return 0

    def _to_ascii(self, string):
        return "".join([
           chr(x) if x >= 0x20 and x <= 0x7e or x == 0xff else "."
           for x in string
       ])

    def format_data(self, data):
        data = bytes(data)
        pos = 0
        formatted_data = ""
        str_fmt = '{0:02X} '
        while pos < len(data) - 16:
            part = data[pos:pos + 16]
            for i, byte in enumerate(part):
                formatted_data += str_fmt.format(byte)

            formatted_data += '\t\t\t'
            formatted_data += self._to_ascii(data[pos:pos + 16])
            formatted_data += '\n'
            pos += 16

        for i, byte in enumerate(data[pos:]):
            formatted_data += str_fmt.format(byte)
        formatted_data += '\t\t\t'
        formatted_data += self._to_ascii(data[pos:])
        # yield (pos, len(self.range.data) - pos, self._to_ascii(self.range.data[pos:]))

        return formatted_data

    def on_message(self, message, data):
        if 'payload' not in message:
            print('payload: ' + message)
            return

        what = message['payload']
        parts = what.split(':::')
        if len(parts) < 2:
            print(what)
            return

        cmd = parts[0]
        if cmd == 'backtrace':
            try:
                self.app_window.backtrace_panel.set_backtrace(json.loads(parts[1]))
            except:
                pass
        elif cmd == 'emulator':
            # on a separate thread to allow js api recursion
            Thread(target=self.emulator.api, args=(parts[1:],)).start()
        elif cmd == 'enumerate_java_classes_start':
            if self.app.get_java_classes_panel() is not None:
                self.app.get_java_classes_panel().on_enumeration_start()
            if self.app.get_java_trace_panel() is not None:
                self.app.get_java_trace_panel().on_enumeration_start()
        elif cmd == 'enumerate_java_classes_match':
            if self.app.get_java_classes_panel() is not None:
                self.app.get_java_classes_panel().on_enumeration_match(parts[1])
            if self.app.get_java_trace_panel() is not None:
                self.app.get_java_trace_panel().on_enumeration_match(parts[1])
        elif cmd == 'enumerate_java_classes_complete':
            self.app_window.get_menu().on_java_classes_enumeration_complete()
            if self.app.get_java_classes_panel() is not None:
                self.app.get_java_classes_panel().on_enumeration_complete()
            if self.app.get_java_trace_panel() is not None:
                self.app.get_java_trace_panel().on_enumeration_complete()
        elif cmd == 'enumerate_java_methods_complete':
            self.onEnumerateJavaMethodsComplete.emit([parts[1], json.loads(parts[2])])
            #self.bus.emit(parts[1], json.loads(parts[2]), parts[1])
        elif cmd == 'ftrace':
            if self.app.get_ftrace_panel() is not None:
                self.app.get_ftrace_panel().append_data(parts[1])
        elif cmd == 'enable_kernel':
            self.app_window.get_menu().enable_kernel_menu()
        elif cmd == 'hook_java_callback':
            h = Hook(Hook.HOOK_JAVA)
            h.set_ptr(1)
            h.set_input(parts[1])
            if self.java_pending_args:
                h.set_condition(self.java_pending_args['condition'])
                h.set_logic(self.java_pending_args['logic'])
                self.java_pending_args = None
            self.java_hooks[h.get_input()] = h
            # self.app_window.hooks_panel.hook_java_callback(h)
            self.onAddJavaHook.emit(h)
        elif cmd == 'hook_native_callback':
            h = Hook(Hook.HOOK_NATIVE)
            h.set_ptr(int(parts[1], 16))
            h.set_input(self.temporary_input)
            h.set_bytes(binascii.unhexlify(parts[2]))
            self.temporary_input = ''
            if self.native_pending_args:
                h.set_condition(self.native_pending_args['condition'])
                h.set_logic(self.native_pending_args['logic'])
                self.native_pending_args = None
            self.hooks[h.get_ptr()] = h
            # self.app_window.hooks_panel.hook_native_callback(h)
            self.onAddNativeHook.emit(h)
        elif cmd == 'hook_onload_callback':
            h = Hook(Hook.HOOK_ONLOAD)
            h.set_ptr(0)
            h.set_input(parts[1])

            self.on_loads[parts[1]] = h
            # self.app_window.hooks_panel.hook_onload_callback(h)
            self.onAddOnLoadHook.emit(h)
        elif cmd == 'java_trace':
            panel = self.app.get_java_trace_panel()
            if panel is None:
                panel = self.app.get_session_ui().add_dwarf_tab(SessionUi.TAB_JAVA_TRACE)
            panel.on_event(parts[1], parts[2], parts[3])
        elif cmd == 'log':
            self.log(parts[1])
        elif cmd == 'memory_scan_match':
            self.onMemoryScanMatch.emit([parts[1], parts[2], json.loads(parts[3])])
            #self.bus.emit(parts[1], parts[2], json.loads(parts[3]))
        elif cmd == 'memory_scan_complete':
            self.app_window.get_menu().on_bytes_search_complete()
            self.onMemoryScanComplete.emit([parts[1] + ' complete', 0, 0])
            #self.bus.emit(parts[1] + ' complete', 0, 0)
        elif cmd == 'onload_callback':
            self.loading_library = parts[1]
            str_fmt = ('Hook onload {0} @thread := {1}'.format(parts[1], parts[3]))
            self.log(str_fmt)
            self.onHitOnLoad.emit([parts[1], parts[2]])
        elif cmd == 'release':
            if parts[1] in self.contexts:
                del self.contexts[parts[1]]
            self.onThreadResumed.emit(int(parts[1]))
        elif cmd == 'set_context':
            data = json.loads(parts[1])
            if 'modules' in data:
                self.onSetModules.emit(data['modules'])
            if 'ranges' in data:
                self.onSetRanges.emit(data['ranges'])

            self.onApplyContext.emit(data)
        elif cmd == 'set_data':
            if data:
                formatted_data = self.format_data(data)
                self.onSetData.emit(['raw', parts[1], data])
            else:
                self.onSetData.emit(['plain', parts[1], str(parts[2])])
        elif cmd == 'script_loaded':
            if self._spawned:
                self.device.resume(self.pid)
        elif cmd == 'tracer':
            self.onTraceData.emit(parts[1])
        elif cmd == 'unhandled_exception':
            # todo
            pass
        elif cmd == 'update_modules':
            modules = json.loads(parts[2])
            # todo update onloads bases
            self.onSetModules.emit(modules)
        elif cmd == 'update_ranges':
            self.onSetRanges.emit(json.loads(parts[2]))
        elif cmd == 'watcher':
            exception = json.loads(parts[1])
            self.log('watcher hit op %s address %s @thread := %s' %
                     (exception['memory']['operation'], exception['memory']['address'], parts[2]))
        elif cmd == 'watcher_added':
            self.onWatcherAdded.emit(parts[1], int(parts[2]))
        elif cmd == 'watcher_removed':
            self.onWatcherRemoved.emit(parts[1])
        else:
            print('unknown message: ' + what)

    def _on_apply_context(self, context_data):
        if 'context' in context_data:
            context = Context(context_data['context'])
            self.contexts[str(context_data['tid'])] = context

            sym = ''
            # if context and context.pc:
            #    name = data['ptr']
            if 'pc' in context.__dict__:
                name = context_data['ptr']
                if context.pc.symbol_name is not None:
                    sym = '(%s - %s)' % (context.pc.symbol_module_name, context.pc.symbol_name)
            else:
                name = context_data['ptr']
            self.app_window.threads.add_context(context_data, library_onload=self.loading_library)
            # check if data['reason'] is 0 (REASON_HOOK)
            if self.loading_library is None and context_data['reason'] == 0:
                self.log('hook %s %s @thread := %d' % (name, sym, context_data['tid']))
            if len(self.contexts.keys()) > 1 and self.app_window.context_panel.have_context():
                return
            # self.app.get_session_ui().request_session_ui_focus()
        else:
            self.arch = context_data['arch']
            self.pointer_size = context_data['pointerSize']
            self.java_available = context_data['java']
            str_fmt = ('injected into := {0:d}'.format(self.pid))
            self.log(str_fmt)

        self.context_tid = context_data['tid']
        if self.loading_library is not None:
            self.loading_library = None

    def on_destroyed(self):
        self._reinitialize()
        str_fmt = ('Detached from {0:d}. Script destroyed.'.format(self.pid))
        self.log(str_fmt)
        self.onScriptDestroyed.emit()

    def add_watcher(self, ptr=None):
        if ptr is None:
            ptr, input = InputDialog.input_pointer(self.app_window)
            if ptr == 0:
                return
        return self.dwarf_api('addWatcher', ptr)

    def dump_memory(self, file_path=None, ptr=0, length=0):
        if ptr == 0:
            ptr, inp = InputDialog.input_pointer(self.app_window)
        if ptr > 0:
            if length == 0:
                accept, length = InputDialog.input(
                    self.app_window, hint='insert length', placeholder='1024')
                if not accept:
                    return
                try:
                    if length.startswith('0x'):
                        length = int(length, 16)
                    else:
                        length = int(length)
                except:
                    return
            if file_path is None:
                r = QFileDialog.getSaveFileName(self.app_window, caption='Save binary dump to file')
                if len(r) == 0 or len(r[0]) == 0:
                    return
                file_path = r[0]
            data = self.read_memory(ptr, length)
            with open(file_path, 'wb') as f:
                f.write(data)

    def dwarf_api(self, api, args=None, tid=0):
        if self.pid == 0 or self.process is None:
            return
        if tid == 0:
            tid = self.context_tid
        if args is not None and not isinstance(args, list):
            args = [args]
        if self.script is None:
            return None
        try:
            return self.script.exports.api(tid, api, args)
        except Exception as e:
            self.log(str(e))
            return None

    def hook_java(self, input=None, pending_args=None):
        if input is None or not isinstance(input, str):
            accept, input = InputDialog.input(
                self.app_window, hint='insert java class or methos',
                placeholder='com.package.class or com.package.class.method')
            if not accept:
                return
        self.java_pending_args = pending_args
        input = input.replace(' ', '')
        self.dwarf_api('hookJava', input)

    def hook_native(self, input=None, pending_args=None, own_input=None):
        if input is None or not isinstance(input, str):
            ptr, input = InputDialog.input_pointer(self.app_window)
        else:
            ptr = utils.parse_ptr(self.app_window.dwarf.dwarf_api('evaluatePtr', input))
        if ptr > 0:
            self.temporary_input = input
            if own_input is not None:
                self.temporary_input = own_input
            self.native_pending_args = pending_args
            self.dwarf_api('hookNative', ptr)

    def hook_onload(self, input_=None):
        if input_ is None or not isinstance(input_, str):
            accept, input_ = InputDialog.input(self.app_window, hint='insert module name', placeholder='libtarget.so')
            if not accept:
                return
            if len(input) == 0:
                return

        if not input_.endswith('.so'):
            input_ += '.so'

        if input_ in self.app_window.dwarf.on_loads:
            return

        self.dwarf_api('hookOnLoad', input_)

    def log(self, what):
        self.onLogToConsole.emit(what)

    def native_tracer_start(self, tid=0):
        if self.native_traced_tid > 0:
            return
        if tid == 0:
            accept, tid = InputDialog.input(self.app_window, hint='insert thread id to trace', placeholder=str(self.pid))
            if not accept:
                return
            try:
                if tid.startswith('0x'):
                    tid = int(tid, 16)
                else:
                    tid = int(tid)
            except:
                return
        self.native_traced_tid = tid
        return self.dwarf_api('startNativeTracer', [tid, True])

    def native_tracer_stop(self):
        if self.native_traced_tid == 0:
            return
        self.dwarf_api('stopNativeTracer')
        if self.app_window.trace_panel is not None:
            self.app_window.trace_panel.stop()
        self.native_traced_tid = 0
        # self.app_window.get_menu().on_native_tracer_change(False)

    def read_memory(self, ptr, len):
        if len > 1024 * 1024:
            position = 0
            next_size = 1024 * 1024
            data = bytearray()
            while True:
                try:
                    data += self.dwarf_api('readBytes', [ptr + position, next_size])
                except:
                    return None
                position += next_size
                diff = len - position
                if diff > 1024 * 1024:
                    next_size = 1024 * 1024
                elif diff > 0:
                    next_size = diff
                else:
                    break
            ret = bytes(data)
            del data
            return ret
        else:
            return self.dwarf_api('readBytes', [ptr, len])

    def remove_watcher(self, ptr):
        return self.dwarf_api('removeWatcher', ptr)

    ###########
    #         #
    # getters #
    #         #
    ###########

    def get_emulator(self):
        return self.emulator

    def get_git(self):
        return self.git

    def get_kernel(self):
        return self.kernel

    def get_loading_library(self):
        return self.loading_library

    def get_native_traced_tid(self):
        return self.native_traced_tid

    def get_prefs(self):
        return self.prefs

    def get_scripts_manager(self):
        return self.script_manager
