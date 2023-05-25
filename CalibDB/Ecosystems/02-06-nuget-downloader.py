import json
from tqdm import *
import urllib.request

json_index_path_url = "https://api.nuget.org/v3/catalog0/index.json"
json_index_path = "nuget_index.json"
urllib.request.urlretrieve(json_index_path_url, json_index_path)

curjson = json.load(open(json_index_path))

print(len(curjson))
nuget_items = curjson['items']



totalnum = 0
for oneitem in tqdm(nuget_items):
    curjsonurl = oneitem['@id']
    curname = str(curjsonurl).split('/')[-1]

    urllib.request.urlretrieve(curjsonurl, "nuget_index_pages/"+curname)
    # print(oneitem['count'])
    totalnum += oneitem['count']
print(totalnum)



