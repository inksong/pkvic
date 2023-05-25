import pickle
from pprint import pprint
from tqdm import *
import time

def normalizestrtoset(inputstr):
    inputstr = str(inputstr).lower()
    spcs = ['!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '-', '_', '.', ',', '/', '|', '[', ']', '{', '}', "'",
            '"', '\\', '+', ' ']
    for one in spcs:
        inputstr = str(inputstr).replace(one, '.')
    tmplist = inputstr.split('.')
    rtnset = set()
    for oneitem in tmplist:
        if len(oneitem) > 1:
            rtnset.add(oneitem)
    return rtnset

from elasticsearch import helpers, Elasticsearch

es = Elasticsearch([{'host': 'localhost', 'port': 9200}], timeout=3600)
print(es)
index_name = 'ecosys_pkg'
doctype = 'ecosys_pkg_info'

def search_db(text):
    searchstr = text + '*'
    body = {
        "query":
            {
                "prefix":
                    {
                        'pkgname.keyword': {
                            "value": text
                        }
                    }
            }
    }
    rtn = es.search(index=index_name, doc_type=doctype, body=body, size=10000)
    hits = rtn['hits']['hits']
    relatedpkgtokens = set()

    if len(hits) > 0:
        for onehit in hits:
            cureco = onehit['_source']['ecosys']
            curpkg = onehit['_source']['pkgname']

            relatedpkgtokens = relatedpkgtokens | normalizestrtoset(curpkg)
    return relatedpkgtokens


def get_es_top_k_from_str(foresstr, ecosys, magictailstr, k):
    if len(magictailstr) > 0:
        body = {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"ecosys": {"query": ecosys}}},
                        {"match": {"pkgname": {"query": foresstr}}},
                        {"match": {"pkgname": {"query": magictailstr}}}
                    ]
                }
            }
        }
    else:
        body = {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"ecosys": {"query": ecosys}}},
                        {"match": {"pkgname": {"query": foresstr}}}
                    ]
                }
            }
        }
    
    rtn = es.search(index=index_name, body=body, size=10000)

    hits = rtn['hits']['hits']
    relatedpkgs = []
    relatedpkgtokens = set()

    if len(hits) > 0:
        for onehit in hits[:k]: 
            cureco = onehit['_source']['ecosys']
            curpkg = onehit['_source']['pkgname']
            relatedpkgs.append(curpkg)
            relatedpkgtokens = relatedpkgtokens | normalizestrtoset(curpkg)

    return relatedpkgtokens, relatedpkgs


def Gen_core_elasticsearch(g, input_tokens, input_conjunctions, BP):
    curtails = set()
    EX = set(input_tokens) | set(input_conjunctions)
    for oneEX in (EX):  # n
        gplus = g + oneEX
        curhit = False
        relatedpkgtokens = search_db(gplus)
        if len(relatedpkgtokens) > 0:
            curhit = True
        if curhit:
            curtails |= Gen_core_elasticsearch(gplus, set(EX), input_conjunctions, BP)
        else:
            if g in BP:
                curtails.add(g)
    return curtails

def Gen_core(g, input_tokens, input_conjunctions, BP):
    curtails = set()
    EX = set(input_tokens) | set(input_conjunctions)
    for oneEX in (EX):  # n
        gplus = g + oneEX
        curhit = False
        for oneBP in BP:  # N
            if oneBP.startswith(gplus):
                curhit = True
        if curhit:
            curtails |= Gen_core(gplus, set(EX), input_conjunctions, BP)
        else:
            if g in BP:
                curtails.add(g)
    return curtails


def Gen(input_tokens, input_conjunctions, input_cureco_identifiers, input_cureco_token_set):
    input_tokens = input_tokens & input_cureco_token_set
    
    print("Gen working...")
    print("input_token len:", len(input_tokens))
    print("input_conjunctions len:", len(input_conjunctions))
    paramlen = len(input_tokens | set(input_conjunctions))
    print("**Param Len:", paramlen)
    
    if paramlen > 200:
        print('[ERR] Too many params, abort.')
        print('input tokens:', input_tokens | set(input_conjunctions))
        return []
    
    g = ''
    start = time.time()
    results = Gen_core_elasticsearch(g, input_tokens, input_conjunctions, input_cureco_identifiers)
    end = time.time()
    
    if (end - start) < 1:
        timecost = 'less than 1s'
    else:
        timecost = str(end - start).split('.')[0] + 's'
    print("**Gen done. \n**Timecost: " + timecost)
    
    if len(results) == 0:
        print('No match found.')
    else:
        print('Found pkg:', list(results))
    
    return results

all_conj = ['!','@','#','$','%','^','&','*','(',')','-','_','.',',','/','|','[',']','{','}',"'",'"','\\','+',' ',':']
short_conj = ['.', '_', '-', ':', '|', '/']

def normalizestrtoset(inputstr):
    inputstr = str(inputstr).lower()
    spcs = ['!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '-', '_', '.', ',', '/', '|', '[', ']', '{', '}', "'",
            '"', '\\', '+', ' ']
    for one in spcs:
        inputstr = str(inputstr).replace(one, '.')
    tmplist = inputstr.split('.')
    rtnset = set()
    for oneitem in tmplist:
        if len(oneitem) > 1:
            rtnset.add(oneitem)
    return rtnset

def get_eco_pickle(ecosys_str):
    f = open('ecosys_pickles/' + ecosys_str + '_id_token_set.pickle', 'rb')
    cureco_token_set = pickle.load(f)
    f.close()
    cureco_id_set = pickle.load(open('ecosys_pickles/' + ecosys_str + '_id_set.pickle', 'rb'))
    return cureco_id_set, cureco_token_set

maven_id_set, maven_token_set = get_eco_pickle('maven')

def gen_from_tokens(probe_set, identifer, cur_conj, cureco_id_set, cureco_token_set):
    cur_match_identifiers = Gen(probe_set, cur_conj, cureco_id_set, cureco_token_set)
    print('cur_match_identifiers:', cur_match_identifiers)
    print('ground truth identifer:', identifer)
    match = False
    for one in cur_match_identifiers:
        if identifer in cur_match_identifiers:
            match = True
        for oneconj in ['/', '|', ':']:
            for anotherconj in ['/', '|', ':']:
                for oneid in cur_match_identifiers:
                    if identifer.replace(oneconj, '#') == oneid.replace(anotherconj, '#'):
                        match = True
    print('**Did we find? ', match)

def get_search_results():
    picklepath = 'all_eco_all_gt_search_results.pickle'
    all_eco_all_gt_search_results = pickle.load(open(picklepath, 'rb'))
    return all_eco_all_gt_search_results

all_eco_all_gt_search_results = get_search_results()


def get_search_results_by_key(input_key, cur_eco_index):
    result = "null"
    for onepair in all_eco_all_gt_search_results:
        curkey = onepair[0]
        cur_search_rtn = onepair[1]
        if curkey == input_key:
            result = cur_search_rtn
    
    relatedtokenset = set()
    for onekey in input_key.split():
        cursplitkey = str(onekey).strip()
        for onepkg in cur_eco_index:
            if cursplitkey in onepkg:
                relatedtokenset |= normalizestrtoset(onepkg)
    result_token_set = normalizestrtoset(result)
    search_related_tokens = result_token_set & relatedtokenset

    return search_related_tokens

timecosts = []

def digest_ner_result_srv(filepath, eco_magictails, oneeco, topK):
    print('eco:', oneeco)
    cureco_id_set, cureco_token_set = get_eco_pickle(oneeco)
    
    srv_ner_rtn = pickle.load(open(filepath, 'rb'))
    
    neronly_es_topk_hit_gjs_4 = []
    neronly_es_topk_hit_gjs_6 = []

    token_after_cover_gjs_9 = []
    token_before_after_es_cover_gjs_10 = []
    before_after_es_pkgs_tokens_len_list = []

    ner_and_search_es_topk_hit_gjs_11 = []
    
    totalJobs = []
    
    for oneitem in tqdm(srv_ner_rtn):
        start = time.time()
        cur_id = oneitem[0]
        cur_text = oneitem[1]
        cur_token_set = oneitem[2]
        cur_ner_labels = oneitem[3]
        
        totalJobs.append(cur_id)
        cur_label_set = set()
        for oneinfo in cur_ner_labels:
            tokenlist = oneinfo[0][0]
            labellist = oneinfo[1][0]
            for index in range(len(tokenlist)):
                if labellist[index] != 'O':
                    cur_label_set.add(str(tokenlist[index]).lower())
        
        # ==== get_search_results_by_key(key) ====
        curkey = " ".join(sorted(list(cur_token_set)))
        tokens_extended = get_search_results_by_key(curkey, cureco_id_set)
        # ======== get_search_results_by_key(key) ========
        
        # ===== get magic tails ======
        magictailstr = ''
        for onetail in eco_magictails:
            magictailstr += ' ' + onetail
        # ===== get magic tails ======
        
        neronly_es_topk_hit_gj_4 = False
        esstr_neronly_beforesearch = ""
        for onekey in cur_label_set:
            esstr_neronly_beforesearch += onekey + ' '
        
        relatedpkgtokens_before_4, relatedpkgs_before_4 = get_es_top_k_from_str(
            esstr_neronly_beforesearch, oneeco, magictailstr, topK)
        
        if isdebug:
            print('relatedpkgs_before_4:', relatedpkgs_before_4)
        
        for onepkg in relatedpkgs_before_4:
            if normalizestrtoset(cur_id) == normalizestrtoset(onepkg):
                if isdebug:
                    print('neronly_es_top50_hit_gj_4 HIT:', onepkg)
                neronly_es_topk_hit_gj_4 = True
        if neronly_es_topk_hit_gj_4:
            neronly_es_topk_hit_gjs_4.append(cur_id)
        
        # ==========Extend=============
        cur_label_set_extended = cur_label_set | set(tokens_extended)
        cur_label_set_extended = cur_label_set_extended | set(eco_magictails)

        neronly_es_topk_hit_gj_6 = False
        esstr_neronly_aftersearch = ""
        for onekey in cur_label_set_extended:
            esstr_neronly_aftersearch += onekey + ' '
        
        relatedpkgtokens_after_6, relatedpkgs_after_6 = get_es_top_k_from_str(
            esstr_neronly_aftersearch, oneeco, magictailstr, topK)
        
        for onepkg in relatedpkgs_after_6:
            if normalizestrtoset(cur_id) == normalizestrtoset(onepkg):
                if isdebug:
                    print('neronly_es_top50_hit_gj_6 HIT:', onepkg)
                neronly_es_topk_hit_gj_6 = True
        if neronly_es_topk_hit_gj_6:
            neronly_es_topk_hit_gjs_6.append(cur_id)
        
        ner_and_search_es_topk_hit_gj_11 = False
        for onepkg in (relatedpkgs_before_4):
            if normalizestrtoset(cur_id) == normalizestrtoset(onepkg):
                ner_and_search_es_topk_hit_gj_11 = True
        
        for onepkg in (relatedpkgs_after_6):
            if normalizestrtoset(cur_id) == normalizestrtoset(onepkg):
                ner_and_search_es_topk_hit_gj_11 = True
        
        if ner_and_search_es_topk_hit_gj_11:
            ner_and_search_es_topk_hit_gjs_11.append(cur_id)

        end = time.time()
        curtime = end-start
        timecosts.append(curtime)
    
    print('\nCur Ecosystem:', oneeco)
    print('neronly_es_topk_hit_gjs_4 Rate:', round(len(neronly_es_topk_hit_gjs_4) / len(totalJobs) * 100, 2), '%')
    print('neronly_es_topk_hit_gjs_6 Rate:', round(len(neronly_es_topk_hit_gjs_6) / len(totalJobs) * 100, 2), '%')
    print('ner_and_search_es_topk_hit_gjs_11 Rate:', round(len(ner_and_search_es_topk_hit_gjs_11) / len(totalJobs) * 100, 2), '%')
    
    return round(len(neronly_es_topk_hit_gjs_4) / len(totalJobs) * 100, 2), \
           round(len(neronly_es_topk_hit_gjs_6) / len(totalJobs) * 100, 2), \
           round(len(ner_and_search_es_topk_hit_gjs_11) / len(totalJobs) * 100, 2)

maven_magictails = ['org', 'io', 'com', 'net', 'core', 'main', 'services', 'api', 'dist',
                    'maven', 'commons', 'plugins', 'kernel', 'runtime', 'impl', 'common',
                    'parent', 'project', 'container', 'server', 'studio', 'web', 'embed', 'handler',
                    'complete', 'java', 'build', 'base', 'client']
default_magictails = []

ecosysnamelist = ['maven', 'pypi', 'gem', 'npm', 'packagist', 'nuget']

import numpy as np
indexlist = range(1,200)
totalratepairs = []
for i in indexlist:
    print('*'*40)
    print('cur top k:', i)
    for oneeco in ecosysnamelist[:]: 
        filepath = '/eco_' + str(oneeco) + '_811_gt/labeled_test_gt.pickle'
        if oneeco == 'maven':
            cur_magictails = maven_magictails
        else:
            cur_magictails = default_magictails
        rate4, rate6,rate11 = digest_ner_result_srv(filepath, cur_magictails, oneeco, i)
        totalratepairs.append([rate4, rate6, rate11])
    

    print('Time Cost')
    print(sum(timecosts) / len(timecosts))  # avg 6.4ms
    print(np.std(timecosts))  # std
    print('=' * 40)

