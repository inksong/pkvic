import sys
import csv
from pprint import pprint
csv.field_size_limit(sys.maxsize)

from tqdm import*
rust_crates_path = "crates.csv"

def readfromcsv(filename,rowidlist):
    csv_reader = csv.reader(open(filename))
    rtnrowlist = []
    for row in tqdm(csv_reader):
        tmprow = []
        for oneid in rowidlist:
            tmprow.append(row[oneid])
        rtnrowlist.append(tmprow)
    return rtnrowlist
# created_at,description,documentation,downloads,homepage,id,
# max_upload_size,name,readme,repository,textsearchable_index_col,
# updated_at
rtnlist = readfromcsv(rust_crates_path, [7,2,4,6])

print(rtnlist[0])
print(rtnlist[1])
print(rtnlist[2])
print(rtnlist[3])

# totalset = set()
# for onepkg in tqdm(rtnlist):
#     totalset.add(onepkg[0])
#
# print(len(rtnlist))
# f = open('rust_crates_packages.list','a')
# for onepkg in tqdm(totalset):
#     f.write(str(onepkg)+'\n')
# f.close()