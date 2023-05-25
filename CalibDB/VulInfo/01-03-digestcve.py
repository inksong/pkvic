# the whole idea
# First parse the definition data with full data
# For example, the CWE, CPE, CAPEC databases of the current time slice
# Detailed steps
# Compare the schema in db, modify sha256 to LSH, and think about whether there is room for optimization in the search overhead
# Parse the CWE database and generate LSH in all db as hash
# parse the CPE database,
# The CPE database will extract a lot of obj during the generation process, fill the obj database, and generate hash
# Parse the CVE database, and there will be associations in the CVE
# CVE will be associated with CWE, and the CVE-CWE link will be resolved into db_link
# CVE will be associated with CPE, and the CVE-CPE link will be resolved into db_link
# CVE will be associated with Ref, and the CVE-Ref link will be resolved into db_link (there is no Ref db at this time)
#
# The CVE database will parse out the data in other databases at the same time
# Verify the integrity of the CWE database (check it, it can be skipped as an optimization)
# Verify the integrity of the CPE database (check it, it can be skipped as an optimization)
# Parsing out Ref, with url, name, refsource, tags, this is parsed into Ref-db

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

from tqdm import *
import sqlite3 as db

calib_db_path = r'../CalibDB.db'

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

import json
import linecache
import sqlite3


import os
nvddatapath = '../../Data/nvd-data/'
rootdir = os.path.join(nvddatapath)

pathlist = []
for (dirpath,dirnames,filenames) in os.walk(rootdir):
    for filename in filenames:
        if os.path.splitext(filename)[1]=='.json' and filename[0]!='.':
            pathlist.append(nvddatapath+filename)
            



manypair = []
refpair = []



for path in tqdm(pathlist):

    cve_json = json.load(open(path))
    cve_items = cve_json['CVE_Items']
    print(len(cve_items))
    
    
    
    for cve_item_probe in tqdm(cve_items):
        
        # print('---------')
        # cve_item_probe = cve_items[0]
        
        # print(cve_item_probe)
        cur_cve_id = cve_item_probe['cve']['CVE_data_meta']['ID']
        
        # print(cur_cve_id)
        
        cur_cve_assigner = cve_item_probe['cve']['CVE_data_meta']['ASSIGNER']
    
        # print(cur_cve_assigner)
    
        cur_affects_vendor = cve_item_probe['cve']['affects']['vendor']['vendor_data']
    
        # print(cur_affects_vendor)
    
        # print('--------Affected Packages----------')
        if len(cur_affects_vendor) > 0:
            # print(len(cur_affects_vendor))
            for oneaffectvendor in cur_affects_vendor:
                # print(oneaffectvendor)
                curvendorname = oneaffectvendor['vendor_name']
                # print(curvendorname)
    
                curproduct = oneaffectvendor['product']['product_data']
                for oneaffectproduct in curproduct:
                    curaffprod = oneaffectproduct['product_name']
                    # print(curaffprod)
    
                    curaffver = oneaffectproduct['version']['version_data']
                    for oneaffver in curaffver:
                        # print(oneaffver)
                        curversionvalue = oneaffver['version_value']
                        curversionnaffected = oneaffver['version_affected']
    
    
                        # print(curvendorname, curaffprod, curversionnaffected, curversionvalue)
    
    
                # print(curproduct)
    
        # print('========Affected Packages==========')
    
        cur_problemtype_list = cve_item_probe['cve']['problemtype']['problemtype_data'][0]['description']
        # print(cur_problemtype_list)
    
    
        if len(cur_problemtype_list)>0:
            # print(len(cur_problemtype_list))
            for onecwe in cur_problemtype_list:
                pass
                # print(onecwe['value'])
    
    
    
        cur_refs = cve_item_probe['cve']['references']['reference_data']
        # print(cur_refs)
        for oneurl in cur_refs:
            cururl = oneurl['url']
            curname = oneurl['name']
            currefsource = oneurl['refsource']
            curtags = oneurl['tags']
    
            if len(curtags)>0:
                for onetag in curtags:
                    curtag = onetag
                    # print(cururl, curname, currefsource, curtag)

                    hashstr = str(cururl)
                    cur_md5 = strTomd5(hashstr)
                    cur_minhash = strTohashbytes(hashstr)
                    
                    refpair.append([str(cururl), str(curname), str(currefsource), str(curtag), str(cur_cve_id), cur_md5, cur_minhash])
    
    
            elif len(curtags)==0:
                curtag = 'None'
                # print(cururl, curname, currefsource, curtag)

                hashstr = str(cururl)
                cur_md5 = strTomd5(hashstr)
                cur_minhash = strTohashbytes(hashstr)
                
                refpair.append([str(cururl), str(curname), str(currefsource), str(curtag), str(cur_cve_id), cur_md5, cur_minhash])
    
    
        cur_description = cve_item_probe['cve']['description']['description_data'][0]['value']
        # print("description:", cur_description)
    
    
        cur_impact = cve_item_probe['impact']

        cur_v2_version = ""
        cur_v2_vectorstring = ""
        cur_v2_accessvector = ""
        cur_v2_accessComplexity = ""
        cur_v2_authentication = ""
        cur_v2_confidentialityImpact = ""
        cur_v2_integrityImpact = ""
        cur_v2_availabilityImpact = ""
        cur_v2_baseScore = ""
        cur_impact_severity = ""
        cur_impact_exploitabilityScore = ""
        cur_impact_impactScore = ""
        cur_impact_acInsufInfo = ""

        cur_impact_obtainAllPrivilege = ""
        cur_impact_obtainUserPrivilege = ""
        cur_impact_obtainOtherPrivilege = ""
        cur_impact_userInteractionRequired = ""
        
        # print(cur_impact)
        try:
            cur_impact_v2 = cur_impact['baseMetricV2']['cvssV2']
            cur_v2_version = cur_impact_v2['version']
            cur_v2_vectorstring = cur_impact_v2['vectorString']
            cur_v2_accessvector = cur_impact_v2['accessVector']
            cur_v2_accessComplexity = cur_impact_v2['accessComplexity']
            cur_v2_authentication = cur_impact_v2['authentication']
            cur_v2_confidentialityImpact = cur_impact_v2['confidentialityImpact']
            cur_v2_integrityImpact = cur_impact_v2['integrityImpact']
            cur_v2_availabilityImpact = cur_impact_v2['availabilityImpact']
            cur_v2_baseScore = cur_impact_v2['baseScore']
        except:
            pass
        
        try:
            cur_impact_severity = cur_impact['baseMetricV2']['severity']
        except:
            cur_impact_severity = ""
        try:
            cur_impact_exploitabilityScore = cur_impact['baseMetricV2']['exploitabilityScore']
        except:
            cur_impact_exploitabilityScore = ""
        try:
            cur_impact_impactScore = cur_impact['baseMetricV2']['impactScore']
        except:
            cur_impact_impactScore = ""
        try:
            cur_impact_acInsufInfo = cur_impact['baseMetricV2']['acInsufInfo']
        except:
            cur_impact_acInsufInfo = ""
        try:
            cur_impact_obtainAllPrivilege = cur_impact['baseMetricV2']['obtainAllPrivilege']
        except:
            cur_impact_obtainAllPrivilege = ""
        try:
            cur_impact_obtainUserPrivilege = cur_impact['baseMetricV2']['obtainUserPrivilege']
        except:
            cur_impact_obtainUserPrivilege = ""
        try:
            cur_impact_obtainOtherPrivilege = cur_impact['baseMetricV2']['obtainOtherPrivilege']
        except:
            cur_impact_obtainOtherPrivilege = ""
        try:
            cur_impact_userInteractionRequired = cur_impact['baseMetricV2']['userInteractionRequired']
        except:
            cur_impact_userInteractionRequired = ""
        
        
        # print(cur_impact_severity, cur_impact_acInsufInfo, cur_impact_obtainOtherPrivilege)
        
        cur_pubdate = cve_item_probe['publishedDate']
        cur_last_modi = cve_item_probe['lastModifiedDate']
        
        # print(cur_pubdate, cur_last_modi)
    
        
        
        hashstr = str(cur_cve_id)+str(cur_description)
        cur_md5 = strTomd5(hashstr)
        cur_minhash = strTohashbytes(hashstr)
        
        manypair.append([cur_cve_id, cur_description, cur_pubdate, cur_last_modi, cur_cve_assigner,
                         cur_v2_accessvector, cur_v2_accessComplexity, cur_v2_authentication, cur_v2_confidentialityImpact, cur_v2_integrityImpact,
                         cur_v2_availabilityImpact, str(cur_v2_baseScore), cur_impact_severity, str(cur_impact_exploitabilityScore), str(cur_impact_impactScore),
                         str(cur_impact_obtainAllPrivilege), str(cur_impact_obtainUserPrivilege), str(cur_impact_obtainOtherPrivilege), str(cur_impact_userInteractionRequired), cur_md5,
                         cur_minhash])
        
# print(len(manypair))
# print(manypair[0])
# print('ready to insert cve_db')
# exec_sql(manypair,
#          "insert into cve_db ("
#          "cve_id, cve_description, cve_date_published, cve_date_last_modified, cve_assigner,"
#          "cve_cvssv2_access_vector, cve_cvssv2_access_complexity, cve_cvssv2_authentication, cve_cvssv2_confidentiality_impact, cve_cvssv2_integrity_impact,"
#          "cve_cvssv2_availability_impact, cve_cvssv2_base_score, cve_impact_severity, cve_impact_exploitability_score, cve_impact_score,"
#          "cve_impact_obtain_all_privilege, cve_impact_obtain_user_privilege, cve_impact_obtain_other_privilege, cve_impact_user_interaction_required, db_uid_md5,"
#          "db_uid_minhash) values("
#          "?,?,?,?,?,"
#          "?,?,?,?,?,"
#          "?,?,?,?,?,"
#          "?,?,?,?,?,"
#          "?)",
#         calib_db_path)
#
#
# print(len(refpair))
# print(refpair[0])
#
# # refpair.append([cururl, curname, currefsource, curtag, cur_cve_id, cur_md5, cur_minhash])
# exec_sql(refpair,
#          "insert into ref_db (ref_url, ref_name, ref_info_source, ref_type, ref_related_cve, db_uid_md5, db_uid_minhash) "
#          "values(?,?,?,?,?,?,?)", calib_db_path)
        
        
        
        
        
        
        