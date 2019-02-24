

from PyQt5 import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *

from capstone import *


class DisasmView(QAbstractScrollArea):


    def __init__(self):
        super(DisasmView, self).__init()

        self.capstone_arch = CS_ARCH_X86
        self.capstone_mode = CS_MODE_32

    

    def on_arch_changed(self):
        if self.dwarf.arch == 'arm64':
            self.cs_arch = CS_ARCH_ARM64
            self.cs_mode = CS_MODE_LITTLE_ENDIAN
        elif self.dwarf.arch == 'arm':
            self.cs_arch = CS_ARCH_ARM
            self.cs_mode = CS_MODE_ARM
        elif self.dwarf.arch == 'ia32':
            self.cs_arch = CS_ARCH_X86
            self.cs_mode = CS_MODE_32
        elif self.cs_arch == 'x64':
            self.cs_arch = CS_ARCH_X86
            self.cs_mode = CS_MODE_64
        if self.dwarf.keystone_installed:
            import keystone.keystone_const as ks
            if self.dwarf.arch == 'arm64':
                self.ks_arch = ks.KS_ARCH_ARM64
                self.ks_mode = ks.KS_MODE_LITTLE_ENDIAN
            elif self.dwarf.arch == 'arm':
                self.ks_arch = ks.KS_ARCH_ARM
                self.ks_mode = ks.KS_MODE_ARM
            elif self.dwarf.arch == 'ia32':
                self.ks_arch = ks.KS_ARCH_X86
                self.ks_mode = ks.KS_MODE_32
            elif self.cs_arch == 'x64':
                self.ks_arch = ks.KS_ARCH_X86
                self.ks_mode = ks.KS_MODE_64
