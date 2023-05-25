import json
import linecache
from tqdm import *
import sqlite3 as db
from pprint import pprint

maven_db_path = "../../Data/maven-repo-index.db"


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


def search_sql(sqlstr, db_path):
    conn = db.connect(db_path)
    print(conn)
    c = conn.cursor()
    rtn_rows = list(c.execute(sqlstr))
    print('rtn_rows')
    conn.close()
    return rtn_rows

mvn_sql = "select u from lucene_data"
rtn_rows = search_sql(mvn_sql, maven_db_path)

uidset = set()

for one in tqdm(rtn_rows):
    if '|' in one[0]:
        curuidlist = one[0].split('|')
        
        curgroupId = curuidlist[0]
        curartId = curuidlist[1]
        
        curver = curuidlist[2]
    
        uid = curgroupId + '|' + curartId + " " + curver
        # print(uid)
        uidset.add(uid)

    

f = open("java_maven_packages_ver.list", 'a')
for oneuid in tqdm(uidset):
    f.write(oneuid+'\n')
f.close()
