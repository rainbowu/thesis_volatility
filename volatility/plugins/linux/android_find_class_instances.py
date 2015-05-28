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
Based on "dalvik_find_class_instance" from Holger Macht
"""

import volatility.obj as obj
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.dalvik as dalvik
import volatility.plugins.linux.android as android
import sqlite3 as sql
import sys

class android_find_class_instances(linux_common.AbstractLinuxCommand):
    """Find all class instances on the heap"""

    def __init__(self, config, *args, **kwargs):
        linux_common.AbstractLinuxCommand.__init__(self, config, *args, **kwargs)
        android.register_option_PID(self._config)
        android.register_option_WRITE_SQL_CACHE(self._config)

    def calculate(self, called=False):
        if not self._config.PID:
            print "This plugin requires a PID to be given via the '-p' switch"
            return
        
        con = android.get_sql_cache_connection(self._config)
        
        if not self._config.WRITE_SQL_CACHE:
            #Check if cache exists (then READ_SQL_CACHE = True)
            with con:
                cur = con.cursor()
                try:
                    cur.execute("SELECT InstanceOffset FROM "+self._config.instTable+" LIMIT 1")
                    row = cur.fetchone()
                    if row:
                        print "Cached data found. The plugin will read from cache"
                        self._config.READ_SQL_CACHE = True
                    else:
                        print "No cached data found. The plugin will write to cache"
                        self._config.READ_SQL_CACHE = False
                except sql.Error, e:
                    print "No cached data found. The plugin will write to cache"
                    self._config.READ_SQL_CACHE = False
                    
            #prevents parallel execution of android_app_generic and this plugin. this would produce incorrect results
            if called and self._config.READ_SQL_CACHE:
                print "Please run android_find_class_instances -p "+self._config.PID+" first"
                sys.exit(1)
        
        #localize heap and set boundaries
        start = 0
        end = 0
        proc_as = None
        for task, vma in dalvik.get_data_section_dalvik_heap(self._config):
            start = vma.vm_start
            end = vma.vm_end
            proc_as = task.get_process_address_space()
            break
            
        if not self._config.READ_SQL_CACHE:
        #Calculate and write cache
        
            with con:
                #setup of tables used for cache
                cur = con.cursor()
                cur.execute("CREATE TABLE IF NOT EXISTS "+self._config.instTable+"(InstanceOffset TEXT UNIQUE ON CONFLICT IGNORE, SystemClassOffset TEXT, Descriptor TEXT, Object TEXT)")
                cur.execute("DELETE FROM "+self._config.instTable)
            
                #process heap and determine all existing objects
                offset = start
                while offset < end: 
                    refObj = obj.Object('Object', offset = offset, vm = proc_as)
                    # the references's .clazz is the corresponding classObject
                    sysClass = refObj.clazz
                    # sanity check
                    if android.is_valid_class(refObj):
                        cur.execute('INSERT INTO '+self._config.instTable+' VALUES(?, ?, ?, ?)', (str(hex(int(offset))), str(hex(int(sysClass))), str(dalvik.getString(sysClass.descriptor)), None))
                        con.commit()

                        yield sysClass, offset, str(dalvik.getString(sysClass.descriptor))
                    
                    # we assume 4 byte alignment, this should be quite save and quarters the scan effort
                    offset += 0x4
            
        else:
        #Read from cache
        
            with con:
                con.row_factory = sql.Row
                cur = con.cursor()
                cur.execute("SELECT * FROM "+self._config.instTable)
                rows = cur.fetchall()
                for row in rows:
                    refObj = obj.Object('Object', offset = int(row["InstanceOffset"], 16), vm = proc_as)
                    sysClass = refObj.clazz
                    try:
                        descriptor = dalvik.getString(sysClass.descriptor)
                        yield sysClass, int(row["InstanceOffset"], 16), str(descriptor)
                    #Sometimes dalvik.getString generates an exception. We have to look further into this
                    except Exception, e:
                        continue
        
    def render_text(self, outfd, data):
        self.table_header(outfd, [("SystemClass", "50"),
                                  ("InstanceOffset", "50"),
                                  ("Descriptor", "50")])
        for sysClass, offset, desc in data:
            self.table_row(outfd,
                           hex(int(sysClass)),
                           hex(int(offset)),
                           desc)
