# Volatility
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

"""
@author:       Holger Macht
@license:      GNU General Public License 2.0 or later
@contact:      holger@homac.de
Modified by Alex Joss & Dario Schwab for android_ plugins
"""

import pprint
import volatility.obj as obj
import volatility.plugins.linux.dalvik as dalvik

dalvik_vtypes = {
    #dalvik/Common.h
    'JValue' : [ 0x4, {
        'boolean' : [ 0x0, ['bool']],
        'int' : [ 0x0, ['int']],
        'char' : [ 0x0, ['char']],
        'short' : [ 0x0, ['short']],
        'long' : [ 0x0, ['long']],
        'double' : [ 0x0, ['double']],
        'float' : [ 0x0, ['float']],
        'byte' : [ 0x0, ['byte']],
        'Object' : [ 0x0, ['address']],
        }],
    #dalvik/oo/Object.h
    'Field' : [ 0x10, {
        'clazz' : [ 0x0, ['pointer', ['ClassObject']]],
        'name' : [ 0x4, ['pointer', ['char']]],
        'signature' : [ 0x8, ['pointer', ['char']]],
        'accessFlags' : [ 0xc, ['unsigned int']],
        }],
    'InstField' : [ 0x14, {
        'clazz' : [ 0x0, ['pointer', ['ClassObject']]],
        'name' : [ 0x4, ['pointer', ['char']]],
        'signature' : [ 0x8, ['pointer', ['char']]],
        'accessFlags' : [ 0xc, ['unsigned int']],
        'byteOffset' : [ 0x10, ['int']],
        }],
    'StaticField' : [ 0x18, {
        'clazz' : [ 0x0, ['pointer', ['ClassObject']]],
        'name' : [ 0x4, ['pointer', ['char']]],
        'signature' : [ 0x8, ['pointer', ['char']]],
        'accessFlags' : [ 0xc, ['unsigned int']],
        # can take up to 8 bytes
        'value' : [ 0x10, ['JValue']],
        }],
    'Object' : [ 0x8, {
        'Object' : [ 0x0, ['address']],
        'clazz' : [ 0x0, ['pointer', ['ClassObject']]],
        'lock' : [ 0x4, ['int']],        
        }],
    'DataObject' : [ 0xc, {
        'clazz' : [ 0x0, ['pointer', ['ClassObject']]],
        'lock' : [ 0x4, ['int']],
        'instanceData' : [ 0x8, ['address']],
        }],
    'StringObject' : [ 0xc, {
        'clazz' : [ 0x0, ['pointer', ['ClassObject']]],
        'lock' : [ 0x4, ['int']],
        'instanceData' : [ 0x8, ['unsigned int']],
        }],
    'ArrayObject' : [ 0x14, {
        'clazz' : [ 0x0, ['pointer', ['ClassObject']]],
        'lock' : [ 0x4, ['int']],
        'length' : [ 0x8, ['unsigned int']],
        #including padding of 4 bytes
        'contents0' : [ 0xc, ['address']],
        'contents1' : [ 0x10, ['address']],
        }],
    'Method' : [ 0x38, {
        'clazz' : [ 0x0, ['pointer', ['ClassObject']]],
        'name' : [ 0x10, ['pointer', ['char']]],
        'shorty' : [ 0x1c, ['pointer', ['char']]],
        'inProfile' : [ 0x34, ['bool']],
        }],
    #libdex/DexFile.h
    'DexOptHeader' : [ 0x4, {
        'magic' : [ 0x0, ['unsigned long long']],
        'dexOffset' : [ 0x8, ['unsigned int']],
        }],
    'DexHeader' : [ 0x4, {
        'fileSize' : [ 0x10, ['unsigned int']],
        }],
    'DexFile' : [ 0x4, {
        'pOptHeader' : [ 0x0, ['pointer', ['DexOptHeader']]],
        'pHeader' : [ 0x4, ['pointer', ['DexHeader']]],
        }],
    #dalvik/DvmDex.h
    'DvmDex' : [ 0x4, {
        'pDexFile' : [ 0x0, ['pointer', ['DexFile']]],
        }],
    #dalvik/oo/Object.h
    'ClassObject' : [ 0xa4, {
        'clazz' : [ 0x0, ['pointer', ['ClassObject']]],
        'lock' : [ 0x4, ['int']],
        'instanceData0': [ 0x8, ['address']],
        'instanceData1': [ 0xc, ['address']],
        'instanceData2': [ 0x10, ['address']],
        'instanceData3': [ 0x14, ['address']],
        'descriptor' : [ 0x18, ['pointer', ['char']]],
        'descriptorAlloc' : [ 0x1c, ['pointer', ['char']]],
        'accessFlags' : [ 0x20, ['unsigned int']],
        'serialNumber' : [ 0x24, ['unsigned int']],
        'pDvmDex' : [ 0x28, ['pointer', ['DvmDex']]],
        'status' : [ 0x2c, ['int']],
        'verifyErrorClass' : [ 0x30, ['address']],
        'initThreadId' : [ 0x34, ['unsigned int']],
        'objectSize' : [ 0x38, ['unsigned int']],
        'elementClass' : [ 0x3c, ['pointer', ['ClassObject']]],
        'arrayDim' : [ 0x40, ['int']],
        'primitiveType' : [ 0x44, ['int']],
        'super' : [ 0x48, ['pointer', ['ClassObject']]],
        'classLoader' : [ 0x4c, ['pointer', ['Object']]],
        'initiatingLoaderList' : [ 0x50, ['int']],
        'interfaceCount' : [ 0x58, ['int']],
        'interfaces' : [ 0x5c, ['pointer', ['pointer', ['ClassObject']]]],
        'directMethodCount' : [ 0x60, ['int']],
        'directMethods' : [ 0x64, ['address']],
        'virtualMethodCount' : [ 0x68, ['int']],
        'virtualMethods' : [ 0x6c, ['pointer', ['Method']]],
        'vtableCount' : [ 0x70, ['int']],
        'vtable' : [ 0x74, ['pointer', ['pointer', ['Method']]]],
        'iftableCount' : [ 0x78, ['int']],
        'iftable' : [ 0x7c, ['address']],
        'ifviPoolCount' : [ 0x80, ['int']],
        'ifviPool' : [ 0x84, ['int']],
        'ifieldCount' : [ 0x88, ['int']],
        'ifieldRefCount' : [ 0x8c, ['int']],
        'ifields' : [ 0x90, ['pointer', ['InstField']]],
        'refOffsets' : [ 0x94, ['int']],
        'sourceFile' : [ 0x98, ['pointer', ['char']]],
        'sfieldCount' : [ 0x9c, ['int']],
        'sfields' : [ 0xa0, ['pointer', ['StaticField']]],
        }],
    #dalvik/Hash.h
    'HashEntry' : [ 0x8, {
        'hashValue' : [ 0x0, ['unsigned int']],
        'data' : [ 0x4, ['pointer', ['void']]],
        }],
    'HashTable' : [ 0x18, {
        'tableSize' : [ 0x0, ['int']],
        'numEntries' : [ 0x4, ['int']],
        'numDeadEntries' : [ 0x8, ['int']],
        'pEntries' : [ 0xc, ['pointer', ['HashEntry']]],
        'freeFunc' : [ 0x10, ['address']],
        'lock' : [ 0x14, ['int']],
        }],
    #dalvik/Globals.h
    'DvmGlobals' : [ 0x1c, {
        'bootClassPathStr' : [ 0x0, ['pointer', ['char']]],
        'classPathStr' : [ 0x4, ['pointer', ['char']]],
        'heapStartingSize' : [ 0x8, ['unsigned int']],
        'heapMaximumSize' : [ 0xc, ['unsigned int']],
        'heapGrowthLimit' : [ 0x10, ['unsigned int']],
        'stackSize' : [ 0x14, ['unsigned int']],
        'verboseGc' : [ 0x18, ['bool']],
        'verboseJni' : [ 0x19, ['bool']],
        'verboseClass' : [ 0x1a, ['bool']],
        'verboseShutdown' : [ 0x1b, ['bool']],
        'jdwpAllowed' : [ 0x1c, ['bool']],
        'jdwpConfigured' : [ 0x1d, ['bool']],
        'jdwpTransport' : [ 0x20, ['int']],
        'jdwpServer' : [ 0x24, ['bool']],
        'jdwpHost' : [ 0x28, ['pointer', ['char']]],
        'jdwpPort' : [ 0x2c, ['int']],
        'jdwpSupend' : [ 0x30, ['bool']],
        'profilerClockSource' : [ 0x34, ['int']],
        'lockProfThreshold' : [ 0x38, ['unsigned int']],
        'vfprintfHook' : [ 0x3c, ['address']],
        'exitHook' : [ 0x40, ['address']],
        'abortHook' : [ 0x44, ['address']],
        'isSensitiveThreadHook' : [ 0x48, ['address']],
        'jniGrefLimit' : [ 0x4c, ['int']],
        'jniTrace' : [ 0x50, ['pointer', ['char']]],
        'reduceSignals' : [ 0x54, ['bool']],
        'noQuitHandler' : [ 0x55, ['bool']],
        'verifyDexChecksum' : [ 0x56, ['bool']],
        'stackTraceFile' : [ 0x58, ['pointer', ['char']]],
        'logStdio' : [ 0x5c, ['bool']],
        'dexOptMode' : [ 0x60, ['int']],
        'classVerifyMode' : [ 0x64, ['int']],
        'generateRegisterMaps' : [ 0x68, ['bool']],
        'registerMapMode' : [ 0x6c, ['int']],
        'monitorVerification' : [ 0x70, ['bool']],
        'dexOptForSmp' : [ 0x71, ['bool']],
        'preciseGc' : [ 0x72, ['bool']],
        'preVerify' : [ 0x73, ['bool']],
        'postVerify' : [ 0x41, ['bool']],
        'concurrentMarkSweep' : [ 0x75, ['bool']],
        'verifyCardTable' : [ 0x76, ['bool']],
        'disableExplicitGc' : [ 0x77, ['bool']],
        'assertionCtrlCount' : [ 0x78, ['int']],
        'assertionCtrl' : [ 0x7c, ['address']],
        'executionMode' : [ 0x80, ['int']],
        'initializing' : [ 0x84, ['bool']],
        'optimizing' : [ 0x85, ['bool']],
        'properties' : [ 0x88, ['address']],
        'bootClassPath' : [ 0x8c, ['address']],
        'bootClassPathOptExtra' : [ 0x90, ['address']],
        'optimizingBootstrapClass' : [ 0x94, ['bool']],
        'loadedClasses' : [ 0x98, ['pointer', ['HashTable']]],
        'classSerialNumber' : [ 0x9c, ['int']],
        'initiatingLoaderList' : [ 0xa0, ['address']],
        'internLock' : [ 0xa4, ['int']],
        'internedStrings' : [ 0xa8, ['address']],
        'literalStrings' : [ 0xac, ['address']],
        'classJavaLangClass' : [ 0xb0, ['address']],
        'offJavaLangRefReference_referent' : [ 0x1c8, ['int']],
        'offJavaLangString_value': [ 0x214, ['int']],
        'offJavaLangString_count': [ 0x218, ['int']],
        'offJavaLangString_offset': [ 0x21c, ['int']],
        'offJavaLangString_hashCode': [ 0x220, ['int']],
        'gcHeap' : [ 0x290, ['address']],
        #TODO: missing objects, but this should be enough for now
        }],
    }

class HashTable(obj.CType):
    """A class extending the Dalvik hash table type"""
    def get_entries(self):
        offset = 0x0
        count = 0
        while offset < self.tableSize * 0x8:
            hashEntry = obj.Object('HashEntry', offset = self.pEntries + offset, vm = self.obj_vm)
            # 0xcbcacccd is HASH_TOMBSTONE for dead entries
            if hashEntry.hashValue == 0 or hashEntry.data == 0xcbcacccd:
                offset += 0x8
                count += 1
                continue

            yield hashEntry.data

            # each HashTable entry is 8 bytes (hash* + data*) on the heap
            offset += 0x8
            count += 1

class ClassObject(obj.CType):
    """A class extending the Dalvik ClassObject type"""

    def getIFields(self):
        i = 0
        while i < self.ifieldCount:
            ifield1 = obj.Object('InstField', offset = self.ifields+i*0x14, vm = self.obj_vm)

            yield ifield1
            i+=1
            
    def getSFields(self):
        i = 0
        while i < self.sfieldCount:
            sfield1 = obj.Object('StaticField', offset = self.sfields+i*0x18, vm = self.obj_vm)
            yield sfield1
            i+=1

    def getIField(self, nr):
        count = 0
        for field in self.getIFields():
            if count == nr:
                return field
            count += 1

    def getIFieldbyName(self, name):
        count = 0
        for field in self.getIFields():
            if dalvik.getString(field.name)+"" == name:
                return field
            count += 1

    def getDirectMethods(self):
        i = 0
        while i < self.directMethodCount:
            method = obj.Object('Method', offset = self.directMethods+i*0x38, vm = self.obj_vm)
            yield method
            i+=1

    def getVirtualMethods(self):
        i = 0
        while i < self.virtualMethodCount:
            method = obj.Object('Method', offset = self.virtualMethods+i*0x38, vm = self.obj_vm)
            yield method
            i+=1

class DalvikObjectClasses(obj.ProfileModification):
    conditions = {'os': lambda x: x == 'linux'}
    before = ['LinuxObjectClasses']

    def modification(self, profile):
        profile.vtypes.update(dalvik_vtypes)
        profile.object_classes.update({'HashTable': HashTable,
                                       'ClassObject': ClassObject})
