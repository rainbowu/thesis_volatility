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
@author:        Alex Joss & Dario Schwab
@institution:   Security Engineering Lab (SEL) @ Bern University of Applied Sciences (www.ti.bfh.ch)                              
@license:       GNU General Public License 2.0 or later
@contact:       alex.joss@bluewin.ch; dario.schwab@gmail.com
"""

import sqlite3 as sql
import volatility.plugins.linux.dalvik as dalvik
import volatility.obj as obj
import hashlib, os, sys, re


# registers a Volatiliy command line argument. Used by the android_* plugins
def register_option_PID(config):
    config.add_option('PID', short_option = 'p', default = None,
                      help = 'Operate on this Process ID',
                      action = 'store', type = 'str')
   
def register_option_WRITE_SQL_CACHE(config):
    #CACHE-SETTINGS:
    #If argument "--write_sql_cache" is given or no cache exists, it will be written
    #Otherwise (no argument given and cache exists), data will be read from db
   config.add_option('WRITE_SQL_CACHE', short_option = '-write_sql_cache',
                     help = 'If set, the results will be written to cache',
                     action = 'store_true', dest = 'write_sql_cache')
   config.READ_SQL_CACHE = False

def register_option_GUI(config):
   config.add_option('GUI', short_option = '-gui',
                     help = 'Shows GUI for easier navigation in results of this plugin. Doesn\'t calculate any data',
                     action = 'store_true', dest = 'gui')
   
def get_sql_cache_connection(config):
    #Definition for all tables used by android_* toolchain
    config.objTable = "android_app_generic_obj_"+str(config.PID)
    config.refTable = "android_app_generic_ref_"+str(config.PID)
    config.refRootTable = "android_app_generic_ref_root_"+str(config.PID)
    config.instTable = "android_find_class_instances_"+str(config.PID)
    config.objAPKTable = "android_app_generic_obj_apk_"+str(config.PID)
    config.refAPKTable = "android_app_generic_ref_apk_"+str(config.PID)
    
    #Setup connection to db in users .cache/volatility folder
    sql_cache_directory = os.path.join((os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache")), "volatility")
    if not os.path.exists(sql_cache_directory):
        os.makedirs(sql_cache_directory)
    sql_cache_filename = md5_from_file(config.LOCATION.lstrip('file:')) + ".db"
    sql_cache = os.path.join(sql_cache_directory, sql_cache_filename)
    
    con = None
    try:
        con = sql.connect(sql_cache)
        cur = con.cursor()
        #Optimization for faster processing
        cur.execute('PRAGMA cache_size=-262144')
        cur.execute('PRAGMA temp_store=MEMORY')
        cur.execute('PRAGMA journal_mode=MEMORY')
        
    except sql.Error, e:
        print "Error %s" % e.args[0]
        sys.exit(1)
    return con

# calculates md5 sum of given file contents
def md5_from_file (fileName, block_size=2**14):
    md5 = hashlib.md5()
    f = open(fileName)
    while True:
        data = f.read(block_size)
        if not data:
            break
        md5.update(data)
    f.close()
    return md5.hexdigest()

#------------- PARSER --------------

def parse_boolean(object):
    return object.boolean
    
def parse_boolean_array(object):
    arr = object.dereference_as('ArrayObject')
    # Length limit to prevent memory exhaustion. Only a guess, may have to be adjusted
    if arr.length < 500:
        count = 0
        result = []
        while count < arr.length:
            tmp = obj.Object('bool', offset= arr.contents1.obj_offset+count*0x1, vm = object.obj_vm)
            result.append(tmp)
            count += 1
        #as_string() represents an array as string for easier reading
        return as_string(result)

def parse_byte(object):
    return object.byte

def parse_byte_array(object):
    arr = object.dereference_as('ArrayObject')
     # Length limit to prevent memory exhaustion. Only a guess, may have to be adjusted
    if arr.length < 500:
        count = 0
        result = []
        while count < arr.length:
            tmp = obj.Object('byte', offset= arr.contents1.obj_offset+count*0x1, vm = object.obj_vm)
            result.append(tmp)
            count += 1
        #as_string() represents an array as string for easier reading
        return as_string(result)

def parse_char(object):
    return object.char

def parse_char_array(object, asString = False):
    try:
        arr = object.dereference_as('ArrayObject')
        # Length limit to prevent memory exhaustion. Only a guess, may have to be adjusted
        if arr.length < 10000:
            # the string has count*2 (2 bytes for each character in unicode) characters
            count = 0
            result = []
            while count < arr.length:
                tmp = obj.Object('char', offset= arr.contents1.obj_offset+count*0x2, vm = object.obj_vm)
                result.append(tmp)
                count += 1
            #as_string() represents an array as string for easier reading
            return as_string(result, asString)
    except:
        return ''

def parse_double(object):
    return object.double

def parse_double_array(object):
    arr = object.dereference_as('ArrayObject')
     # Length limit to prevent memory exhaustion. Only a guess, may have to be adjusted
    if arr.length < 500:
        count = 0
        result = []
        while count < arr.length:
            tmp = obj.Object('double', offset= arr.contents1.obj_offset+count*0x8, vm = object.obj_vm)
            result.append(tmp)
            count += 1
        #as_string() represents an array as string for easier reading
        return as_string(result)

def parse_float(object):
    return object.float

def parse_float_array(object):
    arr = object.dereference_as('ArrayObject')
     # Length limit to prevent memory exhaustion. Only a guess, may have to be adjusted
    if arr.length < 500:
        count = 0
        result = []
        while count < arr.length:
            tmp = obj.Object('float', offset= arr.contents1.obj_offset+count*0x4, vm = object.obj_vm)
            result.append(tmp)
            count += 1
        #as_string() represents an array as string for easier reading
        return as_string(result)

def parse_int(object):
    return object.int

def parse_int_array(object):
    arr = object.dereference_as('ArrayObject')
    # Length limit to prevent memory exhaustion. Only a guess, may have to be adjusted
    if arr.length < 500:
        count = 0
        result = []
        while count < arr.length:
            tmp = obj.Object('int', offset= arr.contents1.obj_offset+count*0x4, vm = object.obj_vm)
            result.append(int(tmp))
            count += 1
        #as_string() represents an array as string for easier reading
        return as_string(result)
    
def parse_long(object):
    return object.long

def parse_long_array(object):
    arr = object.dereference_as('ArrayObject')
     # Length limit to prevent memory exhaustion. Only a guess, may have to be adjusted
    if arr.length < 500:
        count = 0
        result = []
        while count < arr.length:
            tmp = obj.Object('long', offset= arr.contents1.obj_offset+count*0x8, vm = object.obj_vm)
            result.append(tmp)
            count += 1
        #as_string() represents an array as string for easier reading
        return as_string(result)
    
def parse_short(object):
    return object.short

def parse_short_array(object):
    arr = object.dereference_as('ArrayObject')
     # Length limit to prevent memory exhaustion. Only a guess, may have to be adjusted
    if arr.length < 500:
        count = 0
        result = []
        while count < arr.length:
            tmp = obj.Object('short', offset= arr.contents1.obj_offset+count*0x2, vm = object.obj_vm)
            result.append(tmp)
            count += 1
        #as_string() represents an array as string for easier reading
        return as_string(result)
    
def parse_integer(integerObj):
    return obj.Object('int', offset = integerObj.obj_offset + integerObj.clazz.getIFieldbyName('value').byteOffset, vm = integerObj.obj_vm)

def parse_integer_array(object):
    arr = object.dereference_as('ArrayObject')
     # Length limit to prevent memory exhaustion. Only a guess, may have to be adjusted
    if arr.length < 500:
        count = 0
        result = []
        while count < arr.length:
            tmp = obj.Object('Object', offset = arr.contents1.obj_offset+count*0x4, vm = object.obj_vm)
            tmp2 = obj.Object('Object', offset = tmp.Object, vm = object.obj_vm)
            count += 1
            result.append(parse_integer(tmp2))
        #as_string() represents an array as string for easier reading
        return as_string(result)

def parse_string(object):
    if dalvik.getString(object.clazz.descriptor)+"" != "Ljava/lang/String;":
        return "This is not a StringObject (%s)" % dalvik.getString(object.clazz.descriptor)
    count = obj.Object('int', offset = object.obj_offset +
                       object.clazz.getIFieldbyName('count').byteOffset, vm = object.obj_vm)
    #print "    count is: %s" % count
    offset = obj.Object('int', offset = object.obj_offset
                        + object.clazz.getIFieldbyName('offset').byteOffset, vm = object.obj_vm)
    #print "    offset is: %s" % offset
    value = obj.Object('address', offset = object.obj_offset +
                       object.clazz.getIFieldbyName('value').byteOffset, vm = object.obj_vm)
    
    if offset == 0:
        if count < 10000:
            ###### Parsing ArrayObject ######
            
            arr = value.dereference_as('ArrayObject')
            # the string has count*2 (2 bytes for each character in unicode) characters
            ch = obj.Object('String', offset = arr.contents1.obj_offset+0x4*offset,
                            vm = object.obj_vm, length = count*2, encoding = "utf16")
            return ch
        else:
            return "WARNING: count was > 1000"
    else:
        return "WARNING: offset was not 0"
    
    #value = obj.Object('int', offset = object.obj_offset + object.clazz.getIFieldbyName('value').byteOffset, vm = object.obj_vm)

def parse_string_array(object):
    arr = object.dereference_as('ArrayObject')
     # Length limit to prevent memory exhaustion. Only a guess, may have to be adjusted
    if arr.length < 500:
        count = 0
        result = []
        while count < arr.length:
            tmp = obj.Object('Object', offset = arr.contents1.obj_offset+count*0x4, vm = object.obj_vm)
            tmp2 = obj.Object('Object', offset = tmp.Object, vm = object.obj_vm)
            count += 1
            result.append(parse_string(tmp2))
        #as_string() represents an array as string for easier reading
        return as_string(result)
    
#represents an array as string for easier reading
def as_string(array, continuous = False):
    arrString = ''
    for value in array:
        arrString += str(value)
        if not continuous:
            arrString +=","
    if not continuous:
        return arrString.rstrip(',')
    else:
        return arrString

#Some sanity  checks to filter out invalid classes  
def is_valid_class(object):
    #Filters out all simple Basetypes and all classes that do not begin with "L"
    descriptor_regex = re.compile(r'^(\[+[BCDFIJSZ]|(\[*L.+))$')
    sysClass = object.clazz
    desc = str(dalvik.getString(sysClass.descriptor))
    
    #descriptor must match definitions
    if descriptor_regex.match(desc):
        #object must have between 0 and 500 ifields. This prevents nearly endless looping on faulty objects. Only a guess, may have to be adjusted.
        if int(sysClass.ifieldCount) >= 0 and int(sysClass.ifieldCount) < 500:
            #sfields pointer must point to sysClass itself. If object has no sfields it can be 0
            if sysClass == sysClass.sfields or sysClass.sfields == 0:
                    return True
    return False

#Checks if ifield descriptor matches with descriptor of its content
def is_valid_ifield(iFieldObj, iFieldDescriptor):
    return str(dalvik.getString(iFieldObj.clazz.descriptor)) == iFieldDescriptor and is_valid_class(iFieldObj)
