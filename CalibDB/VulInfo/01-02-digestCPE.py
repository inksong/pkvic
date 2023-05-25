import json
import linecache
from tqdm import *
import sqlite3 as db
from pprint import pprint
# CPE uses XML parsing
# Read all CPE information into CalibDB.cpe_db

path_cpe = r'../../Data/official-cpe-dictionary_v2.3.xml'


from collections     import defaultdict
from io              import BytesIO

from xml.sax import make_parser
from xml.sax.handler import ContentHandler
from xml.sax.handler import feature_namespaces

# Put all ref urls directly into url_db as urls, and label them

# cpe:
#   cpe_item_name
#   cpe_title
#   cpe23_item_name

from cpe import CPE

def detailcpestr(cpestr):
    c = CPE(cpestr)
    curclass = c.get_part()
    vendor = c.get_vendor()
    product = c.get_product()
    version = c.get_version()
    update = c.get_update()
    edition = c.get_edition()
    language = c.get_language()
    sw_edition = c.get_software_edition()
    t_software = c.get_target_software()
    t_hardware = c.get_target_hardware()
    other = c.get_other()

    return [curclass, vendor, product, version, update, edition, language, sw_edition, t_software, t_hardware, other]


cpe_db = dict()
cpe_url_db = [] # cpe23name:url:urlType

class Handler_CPE(ContentHandler):
    
    def __init__(self):
        self.CurrentData = ""
        self.cpedict = dict()
        
        self.cpeName = ""
        self.cpeTitle = ""
        
        self.cpe23Name = ""

        self.part = ""
        self.vendor = ""
        self.product = ""
        self.version = ""
        self.update = ""
        self.edition = ""
        self.language = ""
        self.sw_edition = ""
        self.t_software = ""
        self.t_hardware = ""
        self.other = ""
        
        
        self.referenceUrl = ""
        self.referenceTag = ""
        

       
    
    def startElement(self, tag, attributes):
        self.CurrentData = tag
        if tag == "cpe-item":
            # print("======= cpe-item =======")
            if attributes.get('name'):
                cpeName = attributes.get('name')
                self.cpeName = cpeName
                print("cpeName:", cpeName)
         
                
                self.cpedict = dict()
                cpe_db[cpeName] = self.cpedict
                cpe_db[cpeName]['name'] = cpeName
                cpe_db[cpeName]['title'] = ""
                cpe_db[cpeName]['cpe23Name'] = ""

                cpe_db[cpeName]['part'] = ""
                cpe_db[cpeName]['vendor'] = ""
                cpe_db[cpeName]['product'] = ""
                cpe_db[cpeName]['version'] = ""
                cpe_db[cpeName]['update'] = ""
                cpe_db[cpeName]['edition'] = ""
                cpe_db[cpeName]['language'] = ""
                cpe_db[cpeName]['sw_edition'] = ""
                cpe_db[cpeName]['t_software'] = ""
                cpe_db[cpeName]['t_hardware'] = ""
                cpe_db[cpeName]['other'] = ""
                
                
        if tag == 'reference':
            if attributes.get('href'):
                href = attributes.get('href')
                self.referenceUrl = href
                print("referenceUrl:", href)

                
                
        if tag == "cpe-23:cpe23-item":
            if attributes.get('name'):
                cpe23Name = attributes.get('name')
                self.cpe23Name = cpe23Name
                print("cpe-23:cpe23-item:", cpe23Name)

                cpe_db[self.cpeName]['cpe23Name'] = self.cpe23Name
                
                c = CPE(self.cpe23Name)

                cpe_db[self.cpeName]['part'] = c.get_part()[0]
                cpe_db[self.cpeName]['vendor'] = c.get_vendor()[0]
                cpe_db[self.cpeName]['product'] = c.get_product()[0]
                cpe_db[self.cpeName]['version'] = c.get_version()[0]
                cpe_db[self.cpeName]['update'] = c.get_update()[0]
                cpe_db[self.cpeName]['edition'] = c.get_edition()[0]
                cpe_db[self.cpeName]['language'] = c.get_language()[0]
                cpe_db[self.cpeName]['sw_edition'] = c.get_software_edition()[0]
                cpe_db[self.cpeName]['t_software'] = c.get_target_software()[0]
                cpe_db[self.cpeName]['t_hardware'] = c.get_target_hardware()[0]
                cpe_db[self.cpeName]['other'] = c.get_other()[0]
                

                
    
    def endElement(self, tag):
        if self.CurrentData == "title":
            print("title:", self.cpeTitle)
            if cpe_db[self.cpeName]['title'] == "":
                cpe_db[self.cpeName]['title'] = self.cpeTitle
        
        elif self.CurrentData == "reference":
            print("referenceTag:", self.referenceTag)
            cpe_db[self.cpeName]['referenceTag'] = self.referenceTag

            cpe_url_db.append([self.cpe23Name, self.referenceUrl, self.referenceTag])
        
    
    def characters(self, content):
        if self.CurrentData == "title":
            if cpe_db[self.cpeName]['title'] == "":
                self.cpeTitle = str(content).strip()
        
        elif self.CurrentData == "reference":
            self.referenceTag = str(content).strip()
        
    
    # def endDocument(self):
    #     print(saint_db)



# cpe23name : url : urlType


def main():
    parser = make_parser()
    parser.setFeature(feature_namespaces, 0)
    handler = Handler_CPE()
    parser.setContentHandler(handler)
    parser.parse(path_cpe)
    
    # pprint(cpe_db)



main()


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


calib_db_path = r'../CalibDB.db'


def cpe_db_to_sqldb_step1():
    manypair = []
    cpe23refpair = []
    
    objpair = []
    
    cpe_ref_link = []
    
    for onekey in tqdm(cpe_db.keys()):
        curcpeid = onekey
        cur_Name = cpe_db[curcpeid]['name']
        cur_Title = cpe_db[curcpeid]['title']
        cur_cpe23name = cpe_db[curcpeid]['cpe23Name']
        
        cur_part = cpe_db[curcpeid]['part']
        cur_vendor = cpe_db[curcpeid]['vendor']
        cur_product = cpe_db[curcpeid]['product']
        cur_version = cpe_db[curcpeid]['version']
        cur_update = cpe_db[curcpeid]['update']
        cur_edition = cpe_db[curcpeid]['edition']
        cur_language = cpe_db[curcpeid]['language']
        cur_sw_edition = cpe_db[curcpeid]['sw_edition']

        cur_t_software = cpe_db[curcpeid]['t_software']
        cur_t_hardware = cpe_db[curcpeid]['t_hardware']
        cur_other = cpe_db[curcpeid]['other']

        
        # cur_hashstr = str(curcpeid) + str(cur_Name) + str(cur_Title) + str(cur_cpe23name)
        # cur_md5 = strTomd5(cur_hashstr)
        # cur_minhash = strTohashbytes(cur_hashstr)
        #
        #
        # manypair.append([str(cur_cpe23name), str(cur_Name), str(cur_Title), str(cur_part), str(cur_vendor),
        #                  str(cur_product), str(cur_version), str(cur_update), str(cur_edition), str(cur_language),
        #                      str(cur_sw_edition), str(cur_t_software), str(cur_t_hardware), str(cur_other), str(cur_md5),
        #                          cur_minhash])

        cur_hashstr = str(cur_vendor) + str(cur_product) + str(cur_version) + str(cur_Title)
        cur_md5 = strTomd5(cur_hashstr)
        cur_minhash = strTohashbytes(cur_hashstr)

        objpair.append([str(cur_vendor), str(cur_product), str(cur_version), str(cur_Title), str(cur_md5), cur_minhash])
    
        
    # print(manypair[0])
    # exec_sql(manypair,
    #          "insert into cpe_db ("
    #          "cpe_23_item_name, cpe_item_name, cpe_item_title, cpe_item_part, cpe_item_vendor, "
    #          "cpe_item_product, cpe_item_version, cpe_item_update, cpe_item_edition, cpe_item_language, "
    #          "cpe_item_sw_edition, cpe_item_target_sw, cpe_item_target_hw, cpe_item_other, db_uid_md5, "
    #          "db_uid_minhash) values("
    #          "?,?,?,?,?,"
    #          "?,?,?,?,?,"
    #          "?,?,?,?,?,"
    #          "?)",
    #          calib_db_path)

    # # cpe_url_db.append([self.cpe23Name, self.referenceUrl, self.referenceTag])
    # # ref_db md5 by url
    # for onepair in tqdm(cpe_url_db):
    #     cur_cpe23 = onepair[0]
    #     cur_refurl = onepair[1]
    #     cur_reftag = onepair[2]
    #
    #     cur_hashstr = str(cur_refurl)
    #     cur_md5 = strTomd5(cur_hashstr)
    #     cur_minhash = strTohashbytes(cur_hashstr)
    #
    #     cpe23refpair.append([cur_refurl, cur_reftag, cur_cpe23, cur_md5, cur_minhash])
    #
    #
    # # print(cpe23refpair[0])
    # exec_sql(cpe23refpair,
    #          "insert into ref_db (ref_url, ref_type, ref_related_cpe23, db_uid_md5, db_uid_minhash) values(?,?,?,?,?)",
    #          calib_db_path)
    
    

    # ###objpair.append([cur_vendor, cur_product, cur_version, cur_Title, cur_md5, cur_minhash])
    
    # objpair.append([str(cur_vendor), str(cur_product), str(cur_version), str(cur_Title), str(cur_md5), cur_minhash])
    exec_sql(objpair,
             "insert into obj_db (obj_vendor_name, obj_product_name, obj_version_value, obj_info, db_uid_md5, db_uid_minhash) "
             "values(?,?,?,?,?,?)",
             calib_db_path)

   

cpe_db_to_sqldb_step1()


#RESULTS:

# cpestrlist = [
# 				'cpe:2.3:a:10-strike:free_photo_viewer:1.3:*:*:*:*:*:*:*',
#                 'cpe:/a:optimalpayments:neteller_direct_payment_api:4.1.6',
#                 'cpe:/h:global_technology_associates:gnat_box_firmware:3.3',
#                 'cpe:/h:avaya:tn2602ap_ip_media_resource_320_circuit_pack:vintage_8_firmware',
#                 'cpe:/h:apple:airport_express_base_station_firmware:4.0.9',
# 				'cpe:/h:ibm:advanced_management_module_firmware:2.50c',
# 				'cpe:/o:linux:linux_kernel:2.6.20.1'
#               ]

#
# for onecpestr in cpestrlist:
#     print(detailcpestr(onecpestr))
#     print('*'*50)


# cpe-23:cpe23-item: cpe:2.3:a:zzzcms:zzzphp:1.8.0:*:*:*:*:*:*:*
# 100%|█████████▉| 532471/532481 [1:07:19<00:00, 134.13it/s]<sqlite3.Connection object at 0x123951f10>
# 100%|██████████| 532481/532481 [1:07:19<00:00, 131.81it/s]
# 100%|██████████| 1222535/1222535 [1:21:58<00:00, 248.57it/s]