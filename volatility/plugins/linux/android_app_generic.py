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

import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.dalvik as dalvik
import volatility.plugins.linux.android_find_class_instances as android_find_class_instances
import volatility.plugins.linux.android as android
import volatility.plugins.linux.android_app_generic_gui as android_app_generic_gui
import volatility.obj as obj
import sqlite3 as sql
import sys

class android_app_generic(linux_common.AbstractLinuxCommand):
    """Automated memory analysis of a generic android app"""

    def __init__(self, config, *args, **kwargs):
        linux_common.AbstractLinuxCommand.__init__(self, config, *args, **kwargs)
        android.register_option_PID(self._config)
        android.register_option_WRITE_SQL_CACHE(self._config)
        android.register_option_GUI(self._config)
        
        if not self._config.PID:
            print "This plugin requires a PID to be given via the '-p' switch"
            sys.exit(1)

    def calculate(self):
        con = android.get_sql_cache_connection(self._config)
        
        self._config.READ_SQL_CACHE = False
        if not self._config.WRITE_SQL_CACHE:
            #Check if cache exists (then READ_SQL_CACHE = True)
            cur = con.cursor()
            try:
                cur.execute('SELECT ObjID FROM '+self._config.objTable+' LIMIT 1')
                row = cur.fetchone()
                if row:
                    print "Cached data found. The plugin will read from cache"
                    self._config.READ_SQL_CACHE = True
                    
            except sql.Error, e:
                print "No cached data found. The plugin will write to cache"
                self._config.READ_SQL_CACHE = False
        
        if not self._config.READ_SQL_CACHE:
        #Calculate and write cache
        
            basetypes = ["B","C","D","F","I","J","S","Z"]
        
            #maps descriptors with parser methods from android.py
            parser = {
                      'B': android.parse_byte,
                      '[B': android.parse_byte_array,
                      'C': android.parse_char,
                      '[C': android.parse_char_array,
                      'D' : android.parse_double,
                      '[D' : android.parse_double_array,
                      'F' : android.parse_float,
                      '[F' : android.parse_float_array,
                      'I': android.parse_int,
                      '[I': android.parse_int_array,
                      'J': android.parse_long,
                      '[J': android.parse_long_array,
                      'S': android.parse_short,
                      '[S': android.parse_short_array,
                      'Z': android.parse_boolean,
                      '[Z': android.parse_boolean_array,
                      'Ljava/lang/String;': android.parse_string,
                      '[Ljava/lang/String;': android.parse_string_array,
                      'Ljava/lang/Integer;': android.parse_integer,
                      '[Ljava/lang/Integer;': android.parse_integer_array
            }
            
            #determines process address space 
            proc_as = None
            for task, vma in dalvik.get_data_section_dalvik_heap(self._config):
                proc_as = task.get_process_address_space()
                break
            
            
            with con:
                #setup of tables used for cache and preprocessing
                cur = con.cursor()
                cur.execute("CREATE TABLE IF NOT EXISTS "+self._config.objTable+" (ObjID INTEGER PRIMARY KEY, InstanceOffset TEXT, Descriptor TEXT, Value TEXT, Object TEXT)")
                cur.execute("DELETE FROM "+self._config.objTable)
                cur.execute("CREATE TABLE IF NOT EXISTS "+self._config.refTable+" (RefID INTEGER PRIMARY KEY, ObjID INT, PtrOffset TEXT, PtrID INT, Name TEXT)")
                cur.execute("DELETE FROM "+self._config.refTable)
                cur.execute("CREATE TABLE IF NOT EXISTS "+self._config.refRootTable+" (RefRootID INTEGER PRIMARY KEY, ObjID INT, RootID INT)")
                cur.execute("DELETE FROM "+self._config.refRootTable)
                
                #reset WRITE_SQL_CACHE before passing it to other plugins
                self._config.WRITE_SQL_CACHE=False
                #process all identified instances from android_find_class_instances
                for sysClass,instance,descriptor in android_find_class_instances.android_find_class_instances(self._config).calculate():
                    tmpObj = obj.Object('Object', offset = instance, vm = proc_as)
                    value = ''
                    #if tmpObj is directly parseable get value
                    if descriptor in parser:
                        value = parser[descriptor](tmpObj)
                    try:
                        cur.execute('INSERT INTO '+self._config.objTable+' VALUES(?,?,?,?,?)', (None, str(hex(int(instance))), str(descriptor), str(value), None))
                    #a problem with 8bit strings occurs sometimes
                    except sql.Error, e:
                        cur.execute('INSERT INTO '+self._config.objTable+' VALUES(?,?,?,?,?)', (None, str(hex(int(instance))), str(descriptor), "<<8bit-error>>", None))
                    con.commit()
                    
                    yield "Object", str(hex(int(instance))), descriptor, '', str(value)
                    
                    objID = cur.lastrowid
                    #Loop through all ifields and check if they can be parsed
                    for ifield in sysClass.getIFields():
                        jValueOffset = instance + ifield.byteOffset
                        jValue = obj.Object('JValue', offset = jValueOffset, vm = proc_as)    
                        iFieldName = str(dalvik.getString(ifield.name))
                        iFieldDescriptor = str(dalvik.getString(ifield.signature))
                        iValue = ''
                        
                        #If ifield contains a basetype, we can parse the JValue directly
                        #Since basetypes are not found during heap-scan (they have no ClassObject and therefore no descriptor), we have to explicitly write them to cache at this point
                        if iFieldDescriptor in basetypes:
                            if iFieldDescriptor in parser:
                                iValue = parser[iFieldDescriptor](jValue)
                                try:
                                    cur.execute('INSERT INTO '+self._config.objTable+' VALUES(?,?,?,?,?)', (None, str(hex(int(jValueOffset))), str(iFieldDescriptor), str(iValue), None))
                                #a problem with 8bit strings occurs sometimes
                                except sql.Error, e:
                                    cur.execute('INSERT INTO '+self._config.objTable+' VALUES(?,?,?,?,?)', (None, str(hex(int(jValueOffset))), str(iFieldDescriptor), "<<8bit-error>>", None))
                            else:        
                                 cur.execute('INSERT INTO '+self._config.objTable+' VALUES(?,?,?,?,?)', (None, str(hex(int(jValueOffset))), str(iFieldDescriptor), '<<not supported yet>>', None))
                            
                            yield "IField", str(hex(int(jValueOffset))), iFieldDescriptor, iFieldName, iValue
                            
                            #Save parent - child pair in reference table for later use
                            refObjID = cur.lastrowid
                            cur.execute("INSERT INTO "+self._config.refTable+" VALUES(?,?,?,?,?)", (None, objID, str(hex(int(jValueOffset))), refObjID, iFieldName))
                        
                        #If ifield is not a basetype, we have to get its classobject to identify and verify it
                        else:   
                            ptrOffset = jValue.Object
                            tmp = obj.Object('Object', offset = ptrOffset, vm = proc_as)
                            #Sanity checks
                            if android.is_valid_ifield(tmp, iFieldDescriptor):
                                #check if the object the ifield points to is really located on the heap and has been found by android_find_class_instances
                                cur.execute("SELECT OID FROM "+self._config.instTable+" WHERE InstanceOffset = ?", (str(hex(int(ptrOffset))),))
                                result = cur.fetchone()
                                if not result:
                                    #Save parent - child pair in reference table for later use but mark child as non existing object
                                    cur.execute("INSERT INTO "+self._config.refTable+" VALUES(?,?,?,?,?)", (None, objID, "<<Pointer to non-existing object>>", None, iFieldName))
                                else:
                                    #Save parent - child pair in reference table for later use
                                    cur.execute("INSERT INTO "+self._config.refTable+" VALUES(?,?,?,?,?)", (None, objID, str(hex(int(ptrOffset))), None, iFieldName))
                            else:
                                #Save parent - child pair in reference table for later use but mark child as invalid
                                cur.execute("INSERT INTO "+self._config.refTable+" VALUES(?,?,?,?,?)", (None, objID, "<<Pointer to invalid object>>", None, iFieldName))
                
                            yield "IField", str(hex(int(ptrOffset))), iFieldDescriptor, iFieldName, ''
                            
            #Create index for faster operations
            print "creating indexes"
            with con:
                cur.execute("DROP INDEX IF EXISTS "+self._config.objTable+"_index")
                cur.execute("CREATE INDEX "+self._config.objTable+"_index ON "+self._config.objTable+" (InstanceOffset, Descriptor)")
            print "done"
            
            #Update remaining PtrID in reference table to speed up further calculations
            print "calculating PtrIDs"
            with con:
                cur.execute("CREATE TEMP TABLE temp_ref AS SELECT * FROM "+self._config.refTable+" WHERE PtrID is NULL")
                cur.execute("SELECT ObjID, InstanceOffset FROM "+self._config.objTable+" WHERE Descriptor NOT IN ('B','C','D','F','I','J','S','Z')")
                rows = cur.fetchall()
                for row in rows:
                    cur.execute("UPDATE temp_ref SET PtrID = ? WHERE PtrOffset = ?", (row[0],row[1]))
                cur.execute("INSERT OR REPLACE INTO "+self._config.refTable+" SELECT * FROM temp_ref")
                cur.execute("DROP TABLE temp_ref")
                cur.execute("DROP INDEX IF EXISTS "+self._config.refTable+"_index")
                cur.execute("CREATE INDEX "+self._config.refTable+"_index ON "+self._config.refTable+" (ObjID, PtrID)")
            print "done"
            
            #Create dummy-object for invalid pointers
            print "creating dummy objects"
            with con:
                cur.execute("SELECT DISTINCT Name, PtrOffset FROM "+self._config.refTable+" WHERE PtrID IS NULL")
                rows = cur.fetchall()
                for row in rows:
                    cur.execute('INSERT INTO '+self._config.objTable+' VALUES(?,?,?,?,?)', (None, str(row[1]), "<<invalid object>>", "<<invalid object>>", None))
                    ObjID = cur.lastrowid
                    cur.execute("UPDATE "+self._config.refTable+" SET PtrID=? WHERE Name=? AND PtrOffset=?",(ObjID, str(row[0]), str(row[1])))
            print "done"
            
            #Write refRoot-table that knows the root object for every object on the heap. Allows for faster tree constructions after searches
            print "writing refRoot-table"
            cur = con.cursor()
            cur.execute("SELECT ObjID FROM "+self._config.objTable+" \
                                        WHERE ObjID NOT IN \
                                        (SELECT PtrID FROM "+self._config.refTable+" \
                                                        WHERE PtrID IS NOT NULL)")
            rows = cur.fetchall()
            for root in rows:
                childrenPassed = []
                self.ref_root_for_all_children(root[0], root[0], childrenPassed, con)
            print "done" 
            
            #Recreate Indexes
            print "recreating indexes"
            with con:
                cur.execute("CREATE INDEX IF NOT EXISTS "+self._config.refRootTable+"_index ON "+self._config.refRootTable+" (ObjID, RootID)")
                cur.execute("DROP INDEX "+self._config.refTable+"_index")
                cur.execute("CREATE INDEX "+self._config.refTable+"_index ON "+self._config.refTable+" (ObjID, PtrID, Name)")
                cur.execute("DROP INDEX IF EXISTS "+self._config.objTable+"_index")
                cur.execute("CREATE INDEX "+self._config.objTable+"_index ON "+self._config.objTable+" (InstanceOffset, Descriptor, Value)")
            print "done"
        
        #Read from cache    
        else:
            
            #Get necessary data from cache
            cur = con.cursor()
            cur.execute('SELECT InstanceOffset, Descriptor, Value FROM '+self._config.objTable)
            rows = cur.fetchall()
            for row in rows:
                #It is not recommended to use this output for further processing. Instead use data stored in the db as it provides more information
                yield "<use cache>", row[0], row[1], "<use cache>", row[2]
                    
    #Recursively sets root object for all its children. Allows for faster tree construction after searches
    def ref_root_for_all_children(self, ParentID, RootID, childrenPassed, con):
        with con:
            cur = con.cursor()
            cur.execute("INSERT INTO "+self._config.refRootTable+" VALUES(?,?,?)",(None, ParentID, RootID))
            cur.execute("SELECT PtrID FROM "+self._config.refTable+" WHERE ObjID=? AND PtrID IS NOT NULL",(ParentID,))
            children = cur.fetchall()
            for child in children:
                if child not in childrenPassed:
                    childrenPassed.append(child)
                    self.ref_root_for_all_children(child[0], RootID, childrenPassed, con)
            
    def render_text(self, outfd, data):
        if self._config.GUI:
            print "Starting GUI now"
            app = android_app_generic_gui.android_app_generic_gui(self._config)
            app.title(__name__)
            app.mainloop()

        else:
            self.table_header(outfd, [("Type", "10"),
                                      ("InstanceOffset", "10"),
                                      ("Descriptor", "30"),
                                      ("Name", "30"),
                                      ("Value", "50")])
            
            for type, instanceOffset, descriptor, name, value in data:
                self.table_row(outfd,
                               type,
                               instanceOffset,
                               descriptor,
                               name,
                               value)
