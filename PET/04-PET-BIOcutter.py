import linecache
from tqdm import *
import random
import os

ecosysnamelist = ['maven', 'pypi', 'gem', 'npm', 'packagist', 'nuget']
filetypes = ['train', 'valid', 'test']


for oneeco in ecosysnamelist:
    for onefiletype in filetypes:
        curpath = 'subpool_NER_' + oneeco + '/' + str(onefiletype)+'.txt'
        print(curpath)
        lines = linecache.getlines(curpath)
        totallists = []
        curlist = []
        curlistlenlist = []
        
        cursplitnum = random.randrange(51, 60)

        for oneline in lines:
            if str(oneline).strip() == 'O':
                continue
            if str(oneline) == '\n':
                if len(curlist) != 0:
                    curlistlenlist.append(len(curlist))
                    totallists.append(curlist)
                curlist = []
            else:
                if len(curlist) > cursplitnum and '-PKG' not in oneline:
                    if len(curlist) != 0:
                        curlistlenlist.append(len(curlist))
                        totallists.append(curlist)
                    curlist = []
                else:
                    curlist.append(oneline)
        
        try:
            os.makedirs('subpool_NER_' + oneeco + '/')
        except:
            pass

        writepath = 'subpool_NER_' + oneeco + '/' + str(onefiletype) + '.txt'
        
        f = open(writepath, 'a')
        for onelist in totallists:
            for oneline in onelist:
                f.write(oneline)
            f.write('\n')
        f.close()
        
