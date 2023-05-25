
# Parse the CWE database and generate LSH in all db as hash

import json
import linecache
from tqdm import *
import sqlite3 as db
from pprint import pprint

cwe_sql = "select * from cwe_db"
db_path = r'../../Data/vuldb_v0.9.5.db'
calib_db_path = r'../CalibDB.db'

def search_sql(sqlstr, db_path):
    
    conn = db.connect(db_path)
    c = conn.cursor()
    rtn_rows = list(c.execute(sqlstr))
    conn.close()
    return rtn_rows
    
def exec_sql(manypair, sqlstr, cur_db_path):
    # manypair = []
    # sqlstr = "insert into cwe_db (cwe_name, db_uid_lsh) values(?,?)"
    # sqlstr = "update pages(id, vulrelated, vultype) VALUES(?,?,?)"
    # sqlstr = "update pages(id, vulrelated, vultype) VALUES(?,?,?)"
    # sqlstr = "update pages set vultype=?, vulrelated=? where id=?"
    
    conn = db.connect(cur_db_path)
    print(conn)
    
    conn.executemany(
        sqlstr,
        manypair)
    conn.commit()
    conn.close()


import linecache

SOURCE_NAME = 'cwe'
SOURCE_FILE = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"

path_cwe = '../../Data/cwec_v4.1.xml'

from xml.sax import make_parser
from xml.sax.handler import ContentHandler
from xml.sax.handler import feature_namespaces

cwe_db = dict()
category_db = dict()
view_db = dict()

class Handler_CWE(ContentHandler):
    
    def __init__(self):
        self.CurrentData = ""
        self.curinfodict = dict()
        
        self.cweid = ""
        self.cweName = ""
        self.Description = ""
        self.Extended_Description = ""
        
        self.Related_Weakness = ""
        self.Language = ""
        self.lanName = ""
        self.lanClass = ""
        self.lanPrevalence = ""
        
        self.Technology = ""
        self.TechnologyPrevalence = ""
        
        self.Background_Detail = ""
        self.type = ""
        
        self.curcatedict = dict()
        self.cateid = ""
        self.catename = ""
        self.catestatus = ""
        self.catesum = ""
        
        self.curviewdict = dict()
        self.viewid = ""
        self.viewName = ""
        self.viewType = ""
        self.viewStatus = ""
        self.viewObjective = ""
        
        
    
    # start element processing
    def startElement(self, tag, attributes):
        self.CurrentData = tag
        if tag == "Weakness":
            # print("======= exploit =======")
            if attributes.get('ID'):
                cweid = attributes.get('ID')
                self.cweid = cweid
                print("cweid:", cweid)
                
                cweName = attributes.get('Name')
                self.cweName = cweName
                print("cweName:", cweName)
                
                self.curinfodict = dict()
                cwe_db[cweid] = self.curinfodict
                cwe_db[cweid]['Description'] = ""
                cwe_db[cweid]['Extended_Description'] = ""
                cwe_db[cweid]['Name'] = self.cweName
                
        if tag == "View":
            if attributes.get('ID'):
                viewid = attributes.get('ID')
                self.viewid = viewid
                print("viewid:", self.viewid)

                viewName = attributes.get('Name')
                self.viewName = viewName
                print("viewName:", viewName)

                viewType = attributes.get('Type')
                self.viewType = viewType
                print("viewType:", viewType)

                viewStatus = attributes.get('Status')
                self.viewStatus = viewStatus
                print("viewStatus:", viewStatus)
                
                self.curviewdict = dict()
                view_db[viewid] = self.curviewdict
                view_db[viewid]['Name'] = self.viewName
                view_db[viewid]['Type'] = self.viewType
                view_db[viewid]['Status'] = self.viewStatus
                view_db[viewid]['Objective'] = ""
                
                
                
        if tag == "Category":
            if attributes.get('ID'):
                cateid = attributes.get('ID')
                self.cateid = cateid
                print("cateid:", cateid)

                catename = attributes.get('Name')
                self.catename = catename
                print("catename:", catename)

                catestatus = attributes.get('Status')
                self.catestatus = catestatus
                print('catestatus:', catestatus)
                
                self.curcatedict = dict()
                # category_db[cateid][]
                category_db[cateid] = self.curcatedict
                category_db[cateid]['Name'] = self.catename
                category_db[cateid]['Status'] = self.catestatus
        if tag == 'Language':
            if attributes.get('Name'):
                lanName = attributes.get('Name')
                self.lanName = lanName
                print("lanName:", lanName)
            if attributes.get('Class'):
                lanClass = attributes.get('Class')
                self.lanClass = lanClass
                print("lanClass:", lanClass)
            if attributes.get('Prevalence'):
                lanPrevalence = attributes.get('Prevalence')
                self.lanPrevalence = lanPrevalence
                print("lanPrevalence:", lanPrevalence)
                
        if tag == "Technology":
            if attributes.get('Class'):
                Technology = attributes.get('Class')
                self.Technology = Technology
                print("Technology:", Technology)
            if attributes.get('Prevalence'):
                TechnologyPrevalence = attributes.get('Prevalence')
                self.TechnologyPrevalence = TechnologyPrevalence
                print("TechnologyPrevalence:", TechnologyPrevalence)
                
        if tag == "Related_Weakness":
            if attributes.get('Nature'):
                Nature = attributes.get('Nature')
                self.Nature = Nature
                print("Nature:", Nature)
                
            if attributes.get('CWE_ID'):
                CWE_ID = attributes.get('CWE_ID')
                self.CWE_ID = CWE_ID
                print("CWE_ID:", CWE_ID)


                
    
    # end element processing
    def endElement(self, tag):
        if self.CurrentData == "Description":
            print("Description:", self.Description)
            if cwe_db[self.cweid]['Description'] == "":
                cwe_db[self.cweid]['Description'] = self.Description


        elif self.CurrentData == "Extended_Description":
            print("Extended_Description:", self.Extended_Description)
            cwe_db[self.cweid]['Extended_Description'] = self.Extended_Description
     
            
        elif self.CurrentData == "Summary":
            print("Summary:", self.catesum)
            category_db[self.cateid]['Summary'] = self.catesum
            
        elif self.CurrentData == "Objective":
            print("Objective:", self.viewObjective)
            view_db[self.viewid]['Objective'] = self.viewObjective
       
    
    # Content Event Handling
    def characters(self, content):
        if self.CurrentData == "Description":
            if cwe_db[self.cweid]['Description'] == "":
                self.Description = str(content).strip()
            
        elif self.CurrentData == "Extended_Description":
            self.Extended_Description = str(content).strip()
            
        elif self.CurrentData == "Summary":
            self.catesum = str(content).strip()
            
        elif self.CurrentData == "Objective":
            self.viewObjective = str(content).strip()
       
    
    # # Called when the end of the document has been parsed
    # def endDocument(self):
    #     print(saint_db)


def main():
    parser = make_parser()
    parser.setFeature(feature_namespaces, 0)
    handler = Handler_CWE()
    parser.setContentHandler(handler)
    parser.parse(path_cwe)
    
    # pprint(cwe_db)
    # pprint(category_db)
    pprint(view_db)

main()





# Generate two sets of md5 as key and minHash array bytes as key ref link

import hashlib
def strTomd5(input):
    return hashlib.md5(input.encode(encoding='UTF-8')).hexdigest()

import pickle
from textacy import preprocessing
from datasketch import MinHash
def strTohashbytes(text):
    text = preprocessing.remove_punctuation(text)
    text = preprocessing.normalize_whitespace(text)
    texts = text.split(' ')
    mHash = MinHash(num_perm=256)
    for onekey in texts:
        mHash.update(onekey.encode('utf8'))
    hashvalues = mHash.hashvalues.tobytes()
    # print(type(hashvalues))

    return hashvalues


import numpy as np
def hashbytesTominHash(hashbytes):
    hasharray = np.frombuffer(hashbytes, dtype=int)
    mx = MinHash(num_perm=256, hashvalues=hasharray)
    return mx
    
    
from datasketch import MinHashLSHForest
def compareAllminHash(curminHash, minHashlist):
    forest = MinHashLSHForest(num_perm=256)
    
    # Add m2 and m3 into the index
    for index in range(len(minHashlist)):
        forest.add(str(index), minHashlist[index])

    
    # IMPORTANT: must call index() otherwise the keys won't be searchable
    forest.index()
    
    # Check for membership using the key
    for index in range(len(minHashlist)):
        print(str(index) in forest)
 
    
    # Using m1 as the query, retrieve top 2 keys that have the higest Jaccard
    result = forest.query(curminHash, 3)
    print("Top 3 candidates", result)

def lshPool():
    test1 = 'Usually, though, we want to work with text that’s been processed by spaCy: tokenized, part-of-speech tagged, parsed, and so on. Since spaCy’s pipelines are language-dependent, we have to load a particular pipeline to match the text; '
    test2 = 'Usually, though, we w tagged, parsed, and so on. Since spaCy’s pipelines are language-dependent, we have to load a particular pipeline to match the text; '
    test3 = "apple is good to eat and health"
    
    
    mhlist = []
    
    mhlist.append(hashbytesTominHash(strTohashbytes(test1)))
    mhlist.append(hashbytesTominHash(strTohashbytes(test2)))
    mhlist.append(hashbytesTominHash(strTohashbytes(test3)))
    
    print(strTomd5(test1))
    print(strTohashbytes(test1))
    
    print(hashbytesTominHash(strTohashbytes(test1)).jaccard(hashbytesTominHash(strTohashbytes(test1))))
    print(hashbytesTominHash(strTohashbytes(test1)).jaccard(hashbytesTominHash(strTohashbytes(test2))))
    print(hashbytesTominHash(strTohashbytes(test1)).jaccard(hashbytesTominHash(strTohashbytes(test3))))
    
    compareAllminHash(hashbytesTominHash(strTohashbytes(test1)), mhlist)


def cwe_db_to_sqldb_step1():
    manypair = []
    typepair = []
    
    for onekey in tqdm(cwe_db.keys()):
        curcweid = onekey
        cur_Name = cwe_db[curcweid]['Name']
        cur_Description = cwe_db[curcweid]['Description']
        cur_Extended_Description = cwe_db[curcweid]['Extended_Description']
        
        cur_hashstr = str(curcweid) + str(cur_Name) + str(cur_Description) + str(cur_Extended_Description)
        cur_md5 = strTomd5(cur_hashstr)
        cur_minhash = strTohashbytes(cur_hashstr)
        cur_type = "Weakness"

        typepair.append([cur_type, curcweid])
        
        manypair.append([curcweid, cur_Name, cur_Description, cur_Extended_Description, cur_md5, cur_minhash])
        # print(type(cur_minhash))
    # print(manypair[0])

    # exec_sql(manypair, "insert into cwe_db (cwe_id, cwe_name, cwe_description, cwe_extended_description, db_uid_md5, db_uid_minhash) values(?,?,?,?,?,?)", calib_db_path)
    exec_sql(typepair, "update cwe_db set cwe_type=? where cwe_id=?", calib_db_path)
    
# cwe_db_to_sqldb_step1()

def cwe_db_to_sqldb_step2():
    manypair = []
    typepair = []
    
    for onekey in tqdm(category_db.keys()):
        curcweid = onekey
        cur_Name = category_db[curcweid]['Name']
        cur_Status = category_db[curcweid]['Status']
        cur_Description = category_db[curcweid]['Summary']
        
        cur_hashstr = str(curcweid) + str(cur_Name) + str(cur_Description) + str(cur_Status)
        cur_md5 = strTomd5(cur_hashstr)
        cur_minhash = strTohashbytes(cur_hashstr)
        cur_type = "Category"

        typepair.append([cur_type, curcweid])
        
        manypair.append([curcweid, cur_Name, cur_Description, cur_Status, cur_md5, cur_minhash])
        
    # print(manypair[0])
    # exec_sql(manypair,
    #          "insert into cwe_db (cwe_id, cwe_name, cwe_description, cwe_status, db_uid_md5, db_uid_minhash) values(?,?,?,?,?,?)",
    #          calib_db_path)

    exec_sql(typepair, "update cwe_db set cwe_type=? where cwe_id=?", calib_db_path)

# cwe_db_to_sqldb_step2()

def cwe_db_to_sqldb_step3():
    manypair = []
    typepair = []
    
    for onekey in tqdm(view_db.keys()):
        curcweid = onekey
        cur_Name = view_db[curcweid]['Name']
        cur_Description = view_db[curcweid]['Objective']
        cur_Status = view_db[curcweid]['Status']
        cur_view_type = view_db[curcweid]['Type']

        cur_type = "View-" + cur_view_type
        cur_hashstr = str(curcweid) + str(cur_Name) + str(cur_Description) + str(cur_Status)
        cur_md5 = strTomd5(cur_hashstr)
        cur_minhash = strTohashbytes(cur_hashstr)
        
        
        
        manypair.append([curcweid, cur_Name, cur_Description, cur_Status, cur_type, cur_md5, cur_minhash])
    
    # print(manypair[0])
    exec_sql(manypair,
             "insert into cwe_db (cwe_id, cwe_name, cwe_description, cwe_status, cwe_type, db_uid_md5, db_uid_minhash) values(?,?,?,?,?,?,?)",
             calib_db_path)
    
    # exec_sql(typepair, "update cwe_db set cwe_type=? where cwe_id=?", calib_db_path)

# cwe_db_to_sqldb_step3()