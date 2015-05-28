# Volatility
# Copyright (C) 2009-2012 Volatile Systems
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details. 
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 
#

import volatility.utils as utils
import volatility.plugins.common as common
import volatility.cache as cache
import volatility.debug as debug
import volatility.obj as obj
import datetime

class _DMP_HEADER(obj.CType):
    """A class for crash dumps"""

    @property
    def SystemUpTime(self):
        """Returns a string uptime"""
                        
        # Some utilities write PAGEPAGE to this field when 
        # creating the dump header. 
        if self.m('SystemUpTime') == 0x4547415045474150:
            return obj.NoneObject("No uptime recorded")
        
        # 1 uptime is 100ns so convert that to microsec
        msec = self.m('SystemUpTime') / 10

        return datetime.timedelta(microseconds = msec)

class CrashInfoModification(obj.ProfileModification):
    """Applies overlays for crash dump headers"""

    conditions = {'os': lambda x: x == 'windows'}

    before = ["WindowsVTypes", "WindowsObjectClasses"]

    def modification(self, profile):
        profile.merge_overlay({
                '_DMP_HEADER' : [ None, {
                    'Comment' : [ None, ['String', dict(length = 128)]],
                    'DumpType' : [ None, ['Enumeration', dict(choices = {0x1: "Full Dump", 0x2: "Kernel Dump"})]],
                    'SystemTime' : [ None, ['WinTimeStamp', {}]],
                }],
                '_DMP_HEADER64' : [ None, {
                    'Comment' : [ None, ['String', dict(length = 128)]],
                    'DumpType' : [ None, ['Enumeration', dict(choices = {0x1: "Full Dump", 0x2: "Kernel Dump"})]],
                    'SystemTime' : [ None, ['WinTimeStamp', {}]],
                }],
            })

        ## Both x86 and x64 use the same structure for now, just
        ## so they can share the same SystemUpTime property.
        profile.object_classes.update({'_DMP_HEADER' : _DMP_HEADER, '_DMP_HEADER64' : _DMP_HEADER})

class CrashInfo(common.AbstractWindowsCommand):
    """Dump crash-dump information"""

    @cache.CacheDecorator("tests/crashinfo")
    def calculate(self):
        """Determines the address space"""
        addr_space = utils.load_as(self._config)

        result = None
        adrs = addr_space
        while adrs:
            if adrs.__class__.__name__ == 'WindowsCrashDumpSpace32' or \
               adrs.__class__.__name__ == 'WindowsCrashDumpSpace64':
                result = adrs
            adrs = adrs.base

        if result is None:
            debug.error("Memory Image could not be identified as a crash dump")

        return result

    def render_text(self, outfd, data):
        """Renders the crashdump header as text"""

        hdr = data.get_header()

        outfd.write("{0}:\n".format(hdr.obj_name))
        outfd.write(" Majorversion:         0x{0:08x} ({1})\n".format(hdr.MajorVersion, hdr.MajorVersion))
        outfd.write(" Minorversion:         0x{0:08x} ({1})\n".format(hdr.MinorVersion, hdr.MinorVersion))
        outfd.write(" KdSecondaryVersion    0x{0:08x}\n".format(hdr.KdSecondaryVersion))
        outfd.write(" DirectoryTableBase    0x{0:08x}\n".format(hdr.DirectoryTableBase))
        outfd.write(" PfnDataBase           0x{0:08x}\n".format(hdr.PfnDataBase))
        outfd.write(" PsLoadedModuleList    0x{0:08x}\n".format(hdr.PsLoadedModuleList))
        outfd.write(" PsActiveProcessHead   0x{0:08x}\n".format(hdr.PsActiveProcessHead))
        outfd.write(" MachineImageType      0x{0:08x}\n".format(hdr.MachineImageType))
        outfd.write(" NumberProcessors      0x{0:08x}\n".format(hdr.NumberProcessors))
        outfd.write(" BugCheckCode          0x{0:08x}\n".format(hdr.BugCheckCode))
        if hdr.obj_name != "_DMP_HEADER64":
            outfd.write(" PaeEnabled            0x{0:08x}\n".format(hdr.PaeEnabled))
        outfd.write(" KdDebuggerDataBlock   0x{0:08x}\n".format(hdr.KdDebuggerDataBlock))
        outfd.write(" ProductType           0x{0:08x}\n".format(hdr.ProductType))
        outfd.write(" SuiteMask             0x{0:08x}\n".format(hdr.SuiteMask))
        outfd.write(" WriterStatus          0x{0:08x}\n".format(hdr.WriterStatus))
        outfd.write(" Comment               {0}\n".format(hdr.Comment))
        outfd.write(" DumpType              {0}\n".format(hdr.DumpType))
        outfd.write(" SystemTime            {0}\n".format(str(hdr.SystemTime or '')))
        outfd.write(" SystemUpTime          {0}\n".format(str(hdr.SystemUpTime or '')))
        outfd.write("\nPhysical Memory Description:\n")
        outfd.write("Number of runs: {0}\n".format(len(data.get_runs())))
        outfd.write("FileOffset    Start Address    Length\n")
        if hdr.obj_name != "_DMP_HEADER64":
            foffset = 0x1000
        else:
            foffset = 0x2000
        run = []

        ## FIXME. These runs differ for x86 vs x64. This is a reminder
        ## for MHL or AW to fix it. 

        for run in data.get_runs():
            outfd.write("{0:08x}      {1:08x}         {2:08x}\n".format(foffset, run[0] * 0x1000, run[1] * 0x1000))
            foffset += (run[1] * 0x1000)
        outfd.write("{0:08x}      {1:08x}\n".format(foffset - 0x1000, ((run[0] + run[1] - 1) * 0x1000)))
