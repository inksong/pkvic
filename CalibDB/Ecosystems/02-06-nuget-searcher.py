import json
from tqdm import *
from pprint import pprint

json_index_path = "nuget_index.json"

import os

nuget_json_path = 'nuget_index_pages/'
rootdir = os.path.join(nuget_json_path)

pathlist = []
for (dirpath, dirnames, filenames) in os.walk(rootdir):
    for filename in filenames:
        if os.path.splitext(filename)[1] == '.json' and filename[0] != '.':
            pathlist.append(nuget_json_path + filename)
            
print(pathlist)
totalcount = 0

totalitemset = set()
totalpairs = []

for onepath in tqdm(pathlist):
    curjson = json.load(open(onepath))
    curcount = int(curjson['count'])
    # print(len(curjson['items']))
    for oneitem in curjson['items']:
        
        curid = oneitem['nuget:id']
        curver = oneitem['nuget:version']
        
        if curid not in totalitemset:
            totalitemset.add(curid)
            totalpairs.append([curid, curver])
    
    totalcount+=curcount

print(totalcount)


f = open('csharp_nuget_packages_ver.list','a')
for onepkgver in tqdm(totalpairs):
    curpkg = onepkgver[0]
    curver = onepkgver[1]
    
    f.write(str(curpkg)+" "+str(curver)+'\n')
f.close()