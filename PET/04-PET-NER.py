from tqdm import *
import sqlite3 as db
import time
import hashlib
import linecache
from pprint import pprint

calib_db_path = r'../CalibDB/CalibDB.db'


def search_sql(sqlstr, db_path):
    conn = db.connect(db_path)
    c = conn.cursor()
    rtn_rows = list(c.execute(sqlstr))
    conn.close()
    return rtn_rows


def worker0():
    print('Loading trackers_db Database...')
    start = time.time()
    sql_searchcvetracker = "select cve_id, ecosys, description, identifier from trackers_db"
    rtn_searchcvetracker = search_sql(sql_searchcvetracker, calib_db_path)
    end = time.time()
    
    print("Done. Load Time: " + str(end - start).split('.')[0] + 's')
    
    cvetrackerdict = dict()
    
    for onepair in tqdm(rtn_searchcvetracker):
        curcveid = onepair[0]
        curecosys = onepair[1]
        curdescrip = onepair[2]
        curidentifier = onepair[3]
        
        if curcveid not in cvetrackerdict.keys():
            cvetrackerdict[curcveid] = []
            cvetrackerdict[curcveid].append([curecosys, curdescrip, curidentifier])
        else:
            cvetrackerdict[curcveid].append([curecosys, curdescrip, curidentifier])
    
    print('cvetrackerdict Done.')
    return cvetrackerdict


cvetrackerdict = worker0()


def worker1():
    print('Loading cve_db Database...')
    start = time.time()
    sql_searchcvedescrip = "select cve_id, cve_description from cve_db"
    rtn_searchcvedescrip = search_sql(sql_searchcvedescrip, calib_db_path)
    end = time.time()
    
    print("Done. Load Time: " + str(end - start).split('.')[0] + 's')
    
    cvedescripecodict = dict()
    
    for onepair in tqdm(rtn_searchcvedescrip):
        curcveid = onepair[0]
        curcvedescripeco = onepair[1]
        
        if curcveid not in cvedescripecodict.keys():
            cvedescripecodict[curcveid] = []
            cvedescripecodict[curcveid].append(curcvedescripeco)
        else:
            cvedescripecodict[curcveid].append(curcvedescripeco)
    
    print('cvedescripdict Done.')
    return cvedescripecodict


cvedescripecodict = worker1()


def worker2():
    print('Loading cve_product_cpe_db Database again...')
    start = time.time()
    sql_searchcveurltextpkg = "select cve_id, cpe_vendor, cpe_product, cpe_part from cve_product_cpe_db"
    rtn_searchcveurltextpkg = search_sql(sql_searchcveurltextpkg, calib_db_path)
    end = time.time()
    
    print("Done. Load Time: " + str(end - start).split('.')[0] + 's')
    
    cvecpedict = dict()
    hashset = set()
    
    for onepair in tqdm(rtn_searchcveurltextpkg):
        
        curcveid = onepair[0]
        cpe_vendor = onepair[1]
        cpe_product = onepair[2]
        cpe_part = onepair[3]
        
        if cpe_part != 'a':
            continue
        
        curhash = hashlib.md5(str(curcveid + cpe_vendor + cpe_product).encode(encoding='UTF-8')).hexdigest()
        if curhash not in hashset:
            hashset.add(curhash)
            if curcveid not in cvecpedict.keys():
                cvecpedict[curcveid] = []
                cvecpedict[curcveid].append(
                    [curcveid, cpe_vendor, cpe_product])
            else:
                cvecpedict[curcveid].append(
                    [curcveid, cpe_vendor, cpe_product])
    
    print('cvecpedict Done.')
    return cvecpedict


cvecpedict = worker2()


def get_all_eco_text():
    # Ecosystem, Description(if have cve, add cvedescrip. if have cpe, add cpe vendor,product)
    eco_maven = []
    eco_pypi = []
    eco_gem = []
    eco_npm = []
    eco_nuget = []
    eco_packagist = []
    
    markset = set()
    for onecve in list(cvetrackerdict.keys()):
        for onepair in cvetrackerdict[onecve]:
            cureco = onepair[0]
            curtext = onepair[1]
            curidentifier = onepair[2]
            
            curdesc = ''
            curcpe = ''
            if onecve in cvedescripecodict.keys():
                curdesc = ' '.join(cvedescripecodict[onecve])
            if onecve in cvecpedict.keys():
                for oneinfo in cvecpedict[onecve]:
                    curcpe += oneinfo[1] + ' ' + oneinfo[2]
            
            cureco = str(cureco).strip()
            curtext = str(curtext).strip()
            curdesc = str(curdesc).strip()
            curcpe = str(curcpe).strip()
            curidentifier = str(curidentifier).strip()
            
            curmark = cureco + curtext + curdesc + curcpe + curidentifier
            
            if cureco == 'maven' and curmark not in markset:
                eco_maven.append([cureco, curidentifier, str(curtext + ' ' + curdesc + ' ' + curcpe).strip()])
                markset.add(curmark)
            if cureco == 'pypi' and curmark not in markset:
                eco_pypi.append([cureco, curidentifier, str(curtext + ' ' + curdesc + ' ' + curcpe).strip()])
                markset.add(curmark)
            if cureco == 'gem' and curmark not in markset:
                eco_gem.append([cureco, curidentifier, str(curtext + ' ' + curdesc + ' ' + curcpe).strip()])
                markset.add(curmark)
            if cureco == 'npm' and curmark not in markset:
                eco_npm.append([cureco, curidentifier, str(curtext + ' ' + curdesc + ' ' + curcpe).strip()])
                markset.add(curmark)
            if cureco == 'nuget' and curmark not in markset:
                eco_nuget.append([cureco, curidentifier, str(curtext + ' ' + curdesc + ' ' + curcpe).strip()])
                markset.add(curmark)
            if cureco == 'packagist' and curmark not in markset:
                eco_packagist.append([cureco, curidentifier, str(curtext + ' ' + curdesc + ' ' + curcpe).strip()])
                markset.add(curmark)
    
    return eco_maven, eco_pypi, eco_gem, eco_npm, eco_packagist, eco_nuget


eco_maven, eco_pypi, eco_gem, eco_npm, eco_packagist, eco_nuget = get_all_eco_text()

import spacy

spacy_nlp = spacy.load('en_core_web_sm')


def digestTextToBIO(text, marklist):
    text = str(text).lower()
    
    text_sentences = spacy_nlp(text)
    sentences = []
    for sentence in text_sentences.sents:
        sentences.append(sentence.text)
    
    wordandmarklist = []
    havePKG = False
    lastMarkHit = 'O'
    for onesentence in sentences:
        doc = spacy_nlp(onesentence)
        words = [token.text for token in doc]
        
        for wordindex in range(len(words)):
            oneword = words[wordindex]
            
            currtn = 'O'
            for onemark in marklist:
                curmark = str(onemark).lower()

                subdoc = spacy_nlp(curmark)
                subcurmarks = [token.text for token in subdoc]
                
                for onesubcurmark in subcurmarks:
                    if oneword == onesubcurmark:
                        currtn = 'B-PKG'
            
            if lastMarkHit == 'B-PKG' or lastMarkHit == 'I-PKG':
                if currtn == 'B-PKG':
                    currtn = 'I-PKG'
            
            lastMarkHit = currtn
            if not len(str(oneword).strip().split(' ')[0]) > 30:
                curtobewrite = str(oneword).strip() + ' ' + str(currtn) + '\n'
                if str(curtobewrite).strip() != 'O':
                    wordandmarklist.append(curtobewrite)
            if currtn == "B-PKG":
                havePKG = True
    
    wordandmarklist.append('\n')
    return wordandmarklist, havePKG


def normalizestrtoset(inputstr):
    inputstr = str(inputstr).lower()
    spcs = ['!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '-', '_', '.', ',', '/', '|', '[', ']', '{', '}', "'",
            '"', '\\', '+', ' ', ':']
    for one in spcs:
        inputstr = str(inputstr).replace(one, '.')
    tmplist = inputstr.split('.')
    rtnset = set()
    for oneitem in tmplist:
        if len(oneitem) > 1:
            rtnset.add(oneitem)
    return rtnset


import os
import random


def biolabel_ner_data(eco_curecosys, curecosys, rseed):
    
    curecosys = 'all'
    
    random.seed(rseed)
    
    ner_curecosys_train = eco_curecosys[:int(0.8 * len(eco_curecosys))]
    ner_curecosys_valid = eco_curecosys[int(0.8 * len(eco_curecosys)):int(0.9 * len(eco_curecosys))]
    ner_curecosys_test = eco_curecosys[int(0.9 * len(eco_curecosys)):]
    
    try:
        os.makedirs('subpool_NER_' + curecosys + '/')
    except:
        pass
    
    totalBIOmark = set()
    for oneinfo in tqdm(ner_curecosys_train):
        cureco = oneinfo[0]
        curidentifier = oneinfo[1]
        marklist = normalizestrtoset(curidentifier)
        curtext = str(oneinfo[2]).replace('###', ' ')
        wordandmarklist, havePKG = digestTextToBIO(curtext, marklist)
        if not havePKG:
            curtext = curtext + ' ' + " ".join(marklist)
            wordandmarklist, havePKG = digestTextToBIO(curtext, marklist)
        curBIOmark = "".join(wordandmarklist)
        if curBIOmark not in totalBIOmark:
            totalBIOmark.add(curBIOmark)
            f = open('subpool_NER_' + curecosys + '/' + 'train.txt', 'a')
            for oneline in wordandmarklist:
                f.write(oneline)
            f.close()
    
    totalBIOmark = set()
    for oneinfo in tqdm(ner_curecosys_valid):
        cureco = oneinfo[0]
        curidentifier = oneinfo[1]
        marklist = normalizestrtoset(curidentifier)
        curtext = str(oneinfo[2]).replace('###', ' ')
        wordandmarklist, havePKG = digestTextToBIO(curtext, marklist)
        if not havePKG:
            curtext = curtext + ' ' + " ".join(marklist)
            wordandmarklist, havePKG = digestTextToBIO(curtext, marklist)
        curBIOmark = "".join(wordandmarklist)
        if curBIOmark not in totalBIOmark:
            totalBIOmark.add(curBIOmark)
            f = open('subpool_NER_' + curecosys + '/' + 'valid.txt', 'a')
            for oneline in wordandmarklist:
                f.write(oneline)
            f.close()
    
    totalBIOmark = set()
    for oneinfo in tqdm(ner_curecosys_test):
        cureco = oneinfo[0]
        curidentifier = oneinfo[1]
        marklist = normalizestrtoset(curidentifier)
        curtext = str(oneinfo[2]).replace('###', ' ')
        wordandmarklist, havePKG = digestTextToBIO(curtext, marklist)
        if not havePKG:
            curtext = curtext + ' ' + " ".join(marklist)
            wordandmarklist, havePKG = digestTextToBIO(curtext, marklist)
        curBIOmark = "".join(wordandmarklist)
        if curBIOmark not in totalBIOmark:
            totalBIOmark.add(curBIOmark)
            f = open('subpool_NER_' + curecosys + '/' + 'test.txt', 'a')
            for oneline in wordandmarklist:
                f.write(oneline)
            f.close()


ecodatalist = [eco_maven, eco_pypi, eco_gem, eco_npm, eco_packagist, eco_nuget]
ecosysnamelist = ['maven', 'pypi', 'gem', 'npm', 'packagist', 'nuget']
for randomseed in range(6):
    for i in range(len(ecodatalist)):
        biolabel_ner_data(ecodatalist[i], ecosysnamelist[i], randomseed)

# train manually labeled ner model
import json
from deeppavlov import configs, build_model, train_model

import os
os.environ["CUDA_DEVICE_ORDER"]="PCI_BUS_ID"
os.environ["CUDA_VISIBLE_DEVICES"]="0"  # specify which GPU(s) to be used

curecosys = 'gem' #change this

with configs.ner.ner_ontonotes_bert.open(encoding='utf8') as f:
        ner_config = json.load(f)

        ner_config['dataset_reader']['data_path'] = 'subpool_NER_'+str(curecosys)  # directory with train.txt, valid.txt and test.txt files
        ner_config['train']['tensorboard_log_dir'] = 'subpool_NER_'+str(curecosys)+'/logs'
        ner_config['train']['batch_size'] = 8
        ner_config['metadata']['variables']['NER_PATH'] = 'subpool_NER_'+str(curecosys)+'/model'
        ner_config['metadata']['download'] = [ner_config['metadata']['download'][-1]]  # do not download the pretrained ontonotes model


        #curmetric = {'name': 'r@2', 'inputs': ['y', 'y_pred']}
        #ner_config['train']['metrics'].append(curmetric)

        #curmetric = {'name': 'r@5', 'inputs': ['y', 'y_pred']}
        #ner_config['train']['metrics'].append(curmetric)

        #curmetric = {'name': 'r@10', 'inputs': ['y', 'y_pred']}
        #ner_config['train']['metrics'].append(curmetric)

        ner_model = train_model(ner_config, download=True)

# valid ner modal
import json
from deeppavlov import configs, build_model, train_model
from tqdm import *

import os

os.environ["CUDA_DEVICE_ORDER"] = "PCI_BUS_ID"
os.environ["CUDA_VISIBLE_DEVICES"] = "0"  # specify which GPU(s) to be used

cur_info_json = json.load(open('cve_pkg_sent.list'))

tagdict = dict()

with configs.ner.ner_ontonotes_bert.open(encoding='utf8') as f:
    ner_config = json.load(f)
    ner_config['dataset_reader'][
        'data_path'] = 'subpool_NER_'+str(curecosys)  # directory with train.txt, valid.txt and test.txt files
    ner_config['train']['tensorboard_log_dir'] = 'subpool_NER_'+str(curecosys)+'/logs'
    ner_config['train']['batch_size'] = 8
    ner_config['metadata']['variables']['NER_PATH'] = 'subpool_NER_'+str(curecosys)+'/model'
    ner_config['metadata']['download'] = [
        ner_config['metadata']['download'][-1]]  # do not download the pretrained ontonotes model
    
    ner_model = build_model(ner_config, download=True)
    totalhit = 0
    totalnum = 0
    totalcveset = set()
    totalcvehitset = set()
    
    for onepair in tqdm(cur_info_json):
        curcve = onepair[0]
        curlabel = onepair[2]
        curtext = onepair[3]
        totalnum += 1
        curHIT = False
        totalcveset.add(curcve)
        try:
            try:
                curRTN = ner_model([curtext])
            except:
                curRTN = ner_model([str(curtext)[:10000]])
        except:
            curRTN = ner_model([str(curtext)[:1000]])
        if 'B-PKG' in str(curRTN):
            curwordslist = curRTN[0][0]
            curtaglist = curRTN[1][0]
            hitfullwordslist = []
            curwordcache = ''
            
            for index in range(len(curtaglist)):
                onetag = curtaglist[index]
                if onetag == 'B-PKG':
                    if curwordcache != '':
                        hitfullwordslist.append(curwordcache)
                        curwordcache = ''
                    curwordcache = curwordslist[index]
                    # appending = True
                if onetag == 'I-PKG':
                    curwordcache += curwordslist[index]
                if onetag == 'O':
                    # appending = False
                    if curwordcache != '':
                        hitfullwordslist.append(curwordcache)
                        curwordcache = ''
=
            for onetagword in hitfullwordslist:
                if onetagword.lower() == curlabel.lower():
                    curHIT = True
                    print(curcve, curlabel, str(curRTN))
                    totalcvehitset.add(curcve)
=
        if curHIT:
            totalhit += 1
        print(totalhit, totalnum, round(totalhit / totalnum, 2))
        print(len(totalcvehitset), len(totalcveset), round(len(totalcvehitset) / len(totalcveset), 2))

