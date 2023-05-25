import json
from tqdm import *

npmjson_path = "npmjs_raw.json"

npmjson = json.load(open(npmjson_path))

print(len(npmjson))
print(len(npmjson['rows']))

totalidset = set()

for onerow in tqdm(npmjson['rows']):
    # print(onerow)
    curid = onerow['id']
    totalidset.add(curid)
    
    
f = open('nodejs_npm_packages.list','a')
for onepkg in tqdm(totalidset):
    f.write(str(onepkg)+'\n')
f.close()