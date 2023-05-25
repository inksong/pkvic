import linecache
from tqdm import *

packlist = ['csharp_nuget_packages.list', # ver
            'python_pypi_packages.list', # 运行中
            'java_maven_packages.list', # 可以有，洗maven就行
            'ruby_rubygem_packages.list',
            'nodejs_npm_packages.list',
            'php_packagist_packages.list',
            'rust_crates_packages.list']




from textacy import preprocessing
from datasketch import MinHash
import elasticsearch.helpers as helper

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


def step1():
    totalpairs = []
    
    for onepack in tqdm(packlist):
        print(onepack)
        cureco = str(onepack).split('_')[0]
        lines = linecache.getlines(onepack)
        
        for oneline in lines:
            curpack = str(oneline).strip()
            # curminhash = strTohashbytes(curpack)
            totalpairs.append([curpack, cureco])
            
    return totalpairs
    

        


from elasticsearch import Elasticsearch
es = Elasticsearch([{'host':'localhost','port':9200}], timeout=3600)

mappings = {
            "mappings": {
                "pkginfo": {
                    "properties": {
                        "id": {
                            "type": "long",
                            "index": "false"
                        },
                        "tags": {
                            "type": "object",
                            "properties": {
                                "ecosys": {"type": "keyword", "index": True},
                                "pkgname": {"type": "keyword", "index": True}
                            }
                        }
                    }
                }
            }
        }

# res = es.indices.create(index='ecosys', body=mappings)


# data = {
#               "id": "1111122222",
#               "tags":{"ecosys":"maven","pkgname": "testpkg"}
#         }
#
# es.index(index="ecopkgs",doc_type="pkginfo",body=data)



packages = []
totalpairs = step1() #[curpack, cureco]

for index in tqdm(range(len(totalpairs))):
    
    data = {
        "id": index,
        "tags": {"ecosys": totalpairs[index][1], "pkgname": totalpairs[index][0]}
    }
    packages.append(data)

actions = [
    {
        '_op_type': 'index',
        '_index': "ecosys",
        '_type': "pkginfo",
        '_source': d
    }
    for d in packages
]

# helper.bulk( es, actions )


