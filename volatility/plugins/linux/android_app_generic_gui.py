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
@author:       	Alex Joss & Dario Schwab
@institution:	Security Engineering Lab (SEL) @ Bern University of Applied Sciences (www.ti.bfh.ch)         		
@license:       GNU General Public License 2.0 or later
@contact:       alex.joss@bluewin.ch; dario.schwab@gmail.com
"""

import volatility.plugins.linux.android as android
import sqlite3 as sql
import re, Tkinter, ttk, sys

class android_app_generic_gui(Tkinter.Tk):
    def __init__(self, config):
        self._config = config
        Tkinter.Tk.__init__(self)
        
        self.con = android.get_sql_cache_connection(self._config)
        self.con.row_factory = sql.Row
        self.cur = self.con.cursor()
        
        #Configure Data
        self.rootObjectsAll = []
        self.rootObjectsCurrent = []
        self.resultObjects = []
        
        #Configure Pages
        self.pageEntries = 25
        self.pageCount = 0
        self.page = (0, self.pageEntries)
        self.rootObjectsCurrentCount = 0
        
        #Start initialization and load of data
        self.initialize_gui()
        self.initial_load_root_objects()
        self.reset_all()
            
    def initialize_gui(self):
        self.grid()
        self.tree = ttk.Treeview(None,columns=('name', 'value', 'descriptor', 'offset'),height=30)
        self.tree.bind('<ButtonRelease-3>', self.copy_to_clipboard)
        
        #Scrollbars
        vsb = ttk.Scrollbar(orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        #Configure columns
        self.tree.heading('#0', text='ObjID')
        self.tree.heading('name', text='Name')
        self.tree.heading('value', text='Value')
        self.tree.heading('descriptor', text='Descriptor')
        self.tree.heading('offset', text='Offset')
        
        self.tree.column('name', anchor='w')
        self.tree.column('value', anchor='w')
        self.tree.column('descriptor', anchor='w')
        self.tree.column('offset', anchor='e')
        
        self.tree.tag_configure('result', background='yellow', foreground='blue')
        self.tree.tag_configure('child0', background='lightgrey')
        self.tree.tag_configure('child1', background='grey')
        
        #Configure rows
        rowCount = 0
        
        #Buttons Search-Actions
        self.buttonExecute = Tkinter.Button(self,text=u"Search",command=self.search)
        self.buttonExecute.grid(column=0, row=rowCount, sticky='EW')
        self.searchAndOrVariable = Tkinter.BooleanVar()
        
        self.buttonExpand = Tkinter.Button(self,text=u"Expand all",command=self.expand_all)
        self.buttonExpand.grid(column=1, row=rowCount, sticky='EW')
        self.buttonCollapse = Tkinter.Button(self,text=u"Collapse all",command=self.collapse_all)
        self.buttonCollapse.grid(column=2, row=rowCount, sticky='EW')
        
        self.buttonClear = Tkinter.Button(self,text=u"Clear all",command=self.reset_all)
        self.buttonClear.grid(column=4, row=rowCount, sticky='EW')
        
        self.grid_rowconfigure(rowCount, weight=0)
        rowCount +=1
        
        #Buttons Search-Configuration
        self.rButtonA = Tkinter.Radiobutton(self,text=u"AND",variable=self.searchAndOrVariable,value=True,indicatoron=0,command=self.reset_gui)
        self.rButtonA.grid(column=0, row=rowCount, sticky='EW')
        self.rButtonO = Tkinter.Radiobutton(self,text=u"OR",variable=self.searchAndOrVariable,value=False,indicatoron=0,command=self.reset_gui)
        self.rButtonO.grid(column=1, row=rowCount, sticky='EW')
        self.rButtonA.select()
        
        self.checkBoxAPKVariable = Tkinter.BooleanVar()
        self.checkBoxAPK = Tkinter.Checkbutton(self,text=u"Filter Classes from APK:",variable=self.checkBoxAPKVariable)
        self.checkBoxAPK.grid(column=2, row=rowCount, sticky='EW')
        self.entryAPKVariable = Tkinter.StringVar()
        self.entryAPK = Tkinter.Entry(self,textvariable=self.entryAPKVariable)
        self.entryAPK.grid(column=3, row=rowCount, sticky='EW')
        
        self.grid_rowconfigure(rowCount, weight=0)
        rowCount +=1
        
        #Entry Fields
        #Entry ObjID
        self.entryObjIDVariable = Tkinter.StringVar()
        self.entryObjID = Tkinter.Entry(self,textvariable=self.entryObjIDVariable)
        self.entryObjID.grid(column=0,row=rowCount,sticky='EW')
        self.entryObjID.bind("<Return>", self.search)
        
        #Entry Name
        self.entryNameVariable = Tkinter.StringVar()
        self.entryName = Tkinter.Entry(self,textvariable=self.entryNameVariable)
        self.entryName.grid(column=1,row=rowCount,sticky='EW')
        self.entryName.bind("<Return>", self.search)
        
        #Entry Value
        self.entryValueVariable = Tkinter.StringVar()
        self.entryValue = Tkinter.Entry(self,textvariable=self.entryValueVariable)
        self.entryValue.grid(column=2,row=rowCount,sticky='EW')
        self.entryValue.bind("<Return>", self.search)
        
        #Entry Descriptor
        self.entryDescVariable = Tkinter.StringVar()
        self.entryDesc = Tkinter.Entry(self,textvariable=self.entryDescVariable)
        self.entryDesc.grid(column=3,row=rowCount,sticky='EW')
        self.entryDesc.bind("<Return>", self.search)
        
        #Entry Offset
        self.entryOffsetVariable = Tkinter.StringVar()
        self.entryOffset = Tkinter.Entry(self,textvariable=self.entryOffsetVariable)
        self.entryOffset.grid(column=4,row=rowCount,sticky='EW')
        self.entryOffset.bind("<Return>", self.search)
        
        self.grid_rowconfigure(rowCount, weight=0)
        rowCount += 1
        
        self.tree.grid(column=0, row=rowCount, columnspan=10, sticky='nsew')
        vsb.grid(column=11, row=rowCount, sticky='ns')
        
        self.grid_rowconfigure(rowCount, weight=1)
        rowCount += 1
        hsb.grid(column=0, row=rowCount, columnspan=10, sticky='ew')
        rowCount +=1
        
        self.buttonFirst = Tkinter.Button(self,text=u"<<",command=self.browse_first)
        self.buttonFirst.grid(column=0, row=rowCount, sticky='EW')
        self.buttonPrev = Tkinter.Button(self,text=u"<",command=self.browse_prev)
        self.buttonPrev.grid(column=1, row=rowCount, sticky='EW')
        self.labelPageVariable = Tkinter.StringVar()
        self.labelPage = Tkinter.Label(self,textvariable=self.labelPageVariable)
        self.labelPage.grid(column=2, row=rowCount, sticky='EW')
        self.buttonNext = Tkinter.Button(self,text=u">",command=self.browse_next)
        self.buttonNext.grid(column=3, row=rowCount, sticky='EW')
        self.buttonLast = Tkinter.Button(self,text=u">>",command=self.browse_last)
        self.buttonLast.grid(column=4, row=rowCount, sticky='EW')
        
        self.grid_rowconfigure(rowCount, weight=0)
        
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)
        self.grid_columnconfigure(2, weight=1)
        self.grid_columnconfigure(3, weight=1)
        self.grid_columnconfigure(4, weight=1)
        self.resizable(True,True)
        self.update()
        self.geometry(self.geometry())

    # copies the specified value from the treeview to clipboard on right mouseclick
    def copy_to_clipboard(self, event=None):
        try:
            if (event.x/(self.tree.winfo_width()/5))-1 >= 0:
                value = self.tree.item(self.tree.focus(), 'values')[(event.x/(self.tree.winfo_width()/5))-1]
            else:
                value = self.tree.focus()
            self.clipboard_clear()
            self.clipboard_append(value)
        
        #If focus is out of the Widget
        except IndexError, e:
            pass
        
    def reset_gui(self):
        if self.searchAndOrVariable.get():
            self.entryObjIDVariable.set(r"%")
            self.entryNameVariable.set(r"%")
            self.entryValueVariable.set(r"%")
            self.entryDescVariable.set(r"%")
            self.entryOffsetVariable.set(r"%")
        else:
            self.entryObjIDVariable.set(r".")
            self.entryNameVariable.set(r".")
            self.entryValueVariable.set(r".")
            self.entryDescVariable.set(r".")
            self.entryOffsetVariable.set(r".")
        self.entryAPKVariable.set(r"%")
    
    def expand_all(self,parent=''):
        for child in self.tree.get_children(parent):
            self.tree.item(child, open=True)
            self.expand_all(child)
            
    def collapse_all(self,parent=''):
        for child in self.tree.get_children(parent):
            self.tree.item(child, open=False)
            self.collapse_all(child)

    def browse_first(self):
        self.page = [(0, self.pageEntries),(0, self.rootObjectsCurrentCount)][self.rootObjectsCurrentCount < self.pageEntries]
        self.update_page()
        
    def browse_prev(self):
        page0 = [self.page[0]-self.pageEntries, 0][self.page[0]-self.pageEntries < 0]
        page1 = [self.page[0], [self.pageEntries,self.rootObjectsCurrentCount][self.rootObjectsCurrentCount < self.pageEntries]][page0 == 0]
        self.page = (page0, page1)
        self.update_page()
        
    def browse_next(self):
        page1 = [self.page[1]+self.pageEntries, self.rootObjectsCurrentCount][self.page[1]+self.pageEntries > self.rootObjectsCurrentCount]
        page0 = [self.page[1], self.rootObjectsCurrentCount-self.pageEntries][page1 == self.rootObjectsCurrentCount]
        self.page = (page0, page1)
        self.update_page()

    def browse_last(self):
        page0 = [self.rootObjectsCurrentCount-self.pageEntries, 0][self.rootObjectsCurrentCount-self.pageEntries < 0]
        self.page = (page0, self.rootObjectsCurrentCount)
        self.update_page()
    
    def initial_load_root_objects(self):
        try:
            self.cur.execute("SELECT ObjID FROM "+self._config.objTable+" \
                                WHERE ObjID NOT IN \
                                (SELECT PtrID FROM "+self._config.refTable+" \
                                                WHERE PtrID IS NOT NULL)")
            rows = self.cur.fetchall()
            if not rows:
                raise sql.Error
        except sql.Error, e:
            print "No Data in Database. Run plugin android_app_generic -p %s (without parameter --gui) to calculate data first." % self._config.PID
            print "Error: %s" % e.args[0]
            sys.exit(1)
        for row in rows:
            self.rootObjectsAll.append(row[0]) 
    
    def tree_load_root_objects(self):
        for child in self.tree.get_children(''):
            self.tree.detach(child)
        
        i = self.page[0]
        while i < self.page[1]:
            try: 
                self.tree.reattach(self.rootObjectsCurrent[i], '', self.rootObjectsCurrent[i])
            except Tkinter.TclError, e:
                self.tree_insert_root_object(self.rootObjectsCurrent[i])
            i += 1
        
    def tree_insert_root_object(self, ObjID):
        self.cur.execute("SELECT Value, Descriptor, InstanceOffset FROM "+self._config.objTable+" WHERE ObjID = ?",(ObjID,))
        row = self.cur.fetchone()
        
        try:
            self.tree.insert('', ObjID, ObjID, text=ObjID, values=('<<Root>>', str(row["Value"]), row["Descriptor"], row["InstanceOffset"]),tag='parent')
        except Tkinter.TclError, e:
            try:
                self.tree.insert('', ObjID, ObjID, text=ObjID, values=('<<Root>>', re.escape(str(row["Value"])), row["Descriptor"], row["InstanceOffset"]),tag='parent')
            except Tkinter.TclError, e:
                print "ERROR: Couldn't insert root object %s" % ObjID
        self.tree_insert_children(ObjID)
            
    def tree_insert_children(self, parentID):
        self.cur.execute("SELECT ao.ObjID as ChildObjID, \
                                ao.Descriptor as ChildDescriptor, \
                                ar.Name as ChildName, \
                                ao.Value as ChildValue, \
                                ao.InstanceOffset as ChildOffset \
                            FROM "+self._config.objTable+" ao \
                            INNER JOIN "+self._config.refTable+" ar ON ao.ObjID = ar.PtrID \
                            WHERE ar.ObjID=?",(parentID,))

        rows = self.cur.fetchall()

        counter = 0
        for row in rows:
            ChildObjID = row["ChildObjID"]
            ChildObjText = row["ChildObjID"]
            if ChildObjID is None:
                ChildObjID = str(parentID)+"_"+str(counter)
                ChildObjText = ChildObjID
                counter += 1
            
            if self.tree.exists(ChildObjID):
                ChildObjID = str(ChildObjID)+"_"+str(parentID)+"_"+str(counter)
                counter += 1
            
            ChildValue = row["ChildValue"]
            if ChildValue is None:
                ChildValue = ''
            
            ChildDesc = row["ChildDescriptor"]
            if ChildDesc is None:
                ChildDesc = ''
            
            try:
                
                self.tree.insert(parentID, 'end', ChildObjID, text=ChildObjText, values=(row["ChildName"], str(ChildValue), ChildDesc, row["ChildOffset"]))
            except Tkinter.TclError, e:
                try:
                    #ttk Treeview can't handle unmatched open braces. re.escape() is a workaround for this issue. 
                    self.tree.insert(parentID, 'end', ChildObjID, text=ChildObjText, values=(row["ChildName"], re.escape(str(ChildValue)), ChildDesc, row["ChildOffset"]))
                except Tkinter.TclError, e:
                    print "ERROR: ObjID ", ChildObjID, " can't be inserted into the Tree"
            self.tree_insert_children(ChildObjID)
            
    def search(self,event=None):
        self.resultObjects = []
        
        modus = "OR"
        if self.searchAndOrVariable.get():
            modus = "AND"
        
        #This search is faster if done this way than it would be with a join query because of the poor sqlite implementation of python
        #Search in objects
        self.cur.execute("SELECT ObjID FROM "+self._config.objTable+" \
                            WHERE ObjID like '"+self.entryObjID.get()+"' "+modus+" \
                                Value like '"+self.entryValue.get()+"' "+modus+" \
                                Descriptor like '"+self.entryDesc.get()+"' "+modus+" \
                                InstanceOffset like '"+self.entryOffset.get()+"'")
        resultsObj = self.cur.fetchall()
        
        #If given, search for name in reference table
        resultRefCheckAnd = []
        if self.entryNameVariable.get() != "%":
            self.cur.execute("SELECT PtrID, coalesce(Name, '<<Root>>') \
                                        FROM "+self._config.refTable+" \
                                WHERE Name like '"+self.entryName.get()+"'")
            resultsRef = self.cur.fetchall()
            
            for resultRef in resultsRef:
                if self.searchAndOrVariable.get():
                    resultRefCheckAnd.append(resultRef["PtrID"])
                else:
                    self.resultObjects.append(resultRef["PtrID"])
        
        #Merge the two results (objects and name (reference table))
        for resultObj in resultsObj:
            if not self.searchAndOrVariable.get() \
                or resultObj["ObjID"] in resultRefCheckAnd \
                or self.entryNameVariable.get() == "%":
                    self.resultObjects.append(resultObj["ObjID"])
        
        resultRootObjects = self.get_root_objects(self.resultObjects)
        
        #Check if objects are in a root object "FromAPK"
        if self.checkBoxAPKVariable.get():
            resultAPKObjIDs = []
            
            #Get root objects for given descriptor
            self.cur.execute("SELECT ObjID FROM "+self._config.objTable+" WHERE Descriptor like '"+self.entryAPKVariable.get()+"'")
            resultsAPK = self.cur.fetchall()
            for row in resultsAPK:
                resultAPKObjIDs.append(row[0])
            
            resultAPKRootObjects = self.get_root_objects(resultAPKObjIDs)
            
            resultRootObjectsToRemove = []
            for resultRootObject in resultRootObjects:
                if resultRootObject not in resultAPKRootObjects:
                    resultRootObjectsToRemove.append(resultRootObject)
                    
            # Evaluates the intersecting set of result set and fromAPK set. Only this will be returned
            for resultRootObjectToRemove in resultRootObjectsToRemove:
                resultRootObjects.remove(resultRootObjectToRemove)
        
        self.reset_root_objects_current(resultRootObjects)
        
    #Only used for search queries
    def get_root_objects(self, objects):
        partitionSize = 750
        rootObjects = []
        for partition in range(0, len(objects), partitionSize):
            objectsPartition = objects[partition:partition+partitionSize]
            placeholders= ', '.join('?' for unused in objectsPartition)
            self.cur.execute("SELECT RootID FROM "+self._config.refRootTable+" WHERE ObjID IN (%s)" % placeholders, objectsPartition)
            rows = self.cur.fetchall()
            for row in rows:
                rootObjects.append(row[0])
        return rootObjects
                
    def reset_all(self):
        self.reset_gui()
        self.reset_data()
    
    def reset_data(self):
        self.resultObjects = []
        self.reset_root_objects_current(self.rootObjectsAll)

    def reset_root_objects_current(self, rootObjectsNew):
        self.rootObjectsCurrent = rootObjectsNew
        self.rootObjectsCurrentCount = len(self.rootObjectsCurrent)
        self.pageCount = self.rootObjectsCurrentCount/self.pageEntries
        self.browse_first()
    
    def update_page(self, event=None):
        self.tree_load_root_objects()
        self.tag_child_objects('')
        pageCount = [self.page[1]/self.pageEntries, 1][self.page[1]/self.pageEntries < 1]
        pageTotal = [self.rootObjectsCurrentCount/self.pageEntries, 1][self.rootObjectsCurrentCount/self.pageEntries < 1]
        self.labelPageVariable.set("Page %s of %s" % (pageCount, pageTotal))
    
    def tag_child_objects(self,parentID):
        childCount = 0
        for child in self.tree.get_children(parentID):  
            if self.resultObjects.count(self.tree.item(child, 'text')):
                self.tree.item(child, tag='result')
                self.tree.see(child)
            else:
                self.tree.item(child, tag='child'+str(childCount))
            self.tag_child_objects(child)
            childCount = (childCount+1)%2
