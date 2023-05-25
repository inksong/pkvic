import linecache
import json
import os
from tqdm import *
from pprint import pprint
import sqlite3 as db

cve_search_patch = '../../Data/circl-cve-search-expanded.json'
calib_db_path = r'../CalibDB.db'
print('ready to read json to cache')
lines = linecache.getlines(cve_search_patch)
print('json load done.')

import hashlib
def strTomd5(input):
    return hashlib.md5(input.encode(encoding='UTF-8')).hexdigest()

from tldextract import extract

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
    print('exec done.')

def main_step1():
    manypair = []
    pairmd5set = set()
    
    for curline in tqdm(lines):
        cur_json = json.loads(curline)
        
        cur_cve = cur_json['id']
        # print("cveid:", cur_cve)
        
        cur_vulnerable_configuration = cur_json['vulnerable_configuration']
        if len(cur_vulnerable_configuration)>0:
            for one_vul_config in cur_vulnerable_configuration:
                cur_one_vul_id = one_vul_config['id']
                cur_one_vul_title = one_vul_config['title']
                
                # print(cur_cve, cur_one_vul_id, cur_one_vul_title)
                
                curmd5 = strTomd5(cur_cve+cur_one_vul_id)
                if curmd5 not in pairmd5set:
                    pairmd5set.add(curmd5)
                    manypair.append([cur_cve, cur_one_vul_id, 'CVE', 'CPE'])
        
        cur_vulnerable_product = cur_json['vulnerable_product']
        if len(cur_vulnerable_product)>0:
            for one_vul_product in cur_vulnerable_product:
                # print(cur_cve, one_vul_product)
                curmd5 = strTomd5(cur_cve + one_vul_product)
                if curmd5 not in pairmd5set:
                    pairmd5set.add(curmd5)
                    manypair.append([cur_cve, one_vul_product, 'CVE', 'CPE'])
    

    
    exec_sql(manypair,
             "insert into db_link (source, target, sourceTable, targetTable) values(?,?,?,?)",
             calib_db_path)

# main_step1()


ecolist = ['JAVA','PYTHON',"CSHARP","RUBY","PHP",""]

ultra_ecolist = ['github','gitlab']

# def gettag(input):

totaldomainset = set()
top_totaldomainset = set()

def main_step2():
    manypair = []
    pairmd5set = set()
    
    for curline in tqdm(lines):
        cur_json = json.loads(curline)
        # pprint(cur_json)
        
        cur_cve = cur_json['id']
        # print("cveid:", cur_cve)
        
        cur_references = cur_json['references']
        # pprint(cur_references)
        for oneref in cur_references:
            curdomain = str(oneref).split('://')[1].split('/')[0]
            # totaldomainset.add(curdomain)

            tsd, td, tsu = extract(oneref)
            # print(tsd, td, tsu)
            top_totaldomainset.add(td+'.'+tsu)
       
    
    # exec_sql(manypair,
    #          "insert into db_link (source, target, sourceTable, targetTable) values(?,?,?,?)",
    #          calib_db_path)


main_step2()


# f = open('ref_domain.list','a')
# for onedomain in totaldomainset:
#     f.write(onedomain+'\n')
# f.close()

f = open('ref_top_domain.list','a')
for onedomain in top_totaldomainset:
    f.write(onedomain+'\n')
f.close()

