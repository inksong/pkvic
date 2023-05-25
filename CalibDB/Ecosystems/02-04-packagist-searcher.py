import json
from pprint import pprint
from tqdm import *

phpjson = json.load(open("../../Data/php_src_list.json"))

pkgnames = phpjson['packageNames']

f = open('php_packagist_packages.list','a')
for onepkg in tqdm(pkgnames):
    f.write(str(onepkg)+'\n')
f.close()