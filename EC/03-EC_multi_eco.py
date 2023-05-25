import json
import linecache
from deeppavlov.core.commands.utils import parse_config
from deeppavlov import train_model, build_model, configs
from tqdm import *

eco_list = ['gem', 'maven', 'npm', 'nuget', 'packagist', 'pypi']
# replace cur_eco with one of the target ecosystem name above, take 'gem' as example.
cur_eco = 'gem'

# use default config file as basic config template
model_config = parse_config('insults_kaggle_bert')

model_config['dataset_reader']['data_path'] = "./subpool_dpp_"+cur_eco
model_config['dataset_reader']['x'] = "text"
model_config['dataset_reader']['y'] = "ecosys"


model_config['metadata']['variables']['ROOT_PATH'] = '.'
model_config['metadata']['variables']['DOWNLOADS_PATH'] = './downloads'
model_config['metadata']['variables']['MODELS_PATH'] = './models'
model_config['metadata']['variables']['MODEL_PATH'] = './models/classifiers/eco_classifier_'+cur_eco+'_torch_bert'
model_config['metadata']['variables']['TRANSFORMER'] = './models/bert-base-uncased'
model_config['chainer']['pipe'][-3]['load_path'] = './models/classifiers/insults_kaggle_torch_bert'
model_config['chainer']['pipe'][-3]['pretrained_bert'] = './models/bert-base-uncased'
model_config['chainer']['pipe'][-3]['save_path'] = './models/classifiers/eco_classifier_'+cur_eco+'_torch_bert/model'
model_config['chainer']['pipe'][1]['load_path'] = './models/classifiers/eco_classifier_'+cur_eco+'_torch_bert/classes.dict'
model_config['chainer']['pipe'][1]['save_path'] = './models/classifiers/eco_classifier_'+cur_eco+'_torch_bert/classes.dict'


model = train_model(model_config)

model.save()

TP = 0
FP = 0
TN = 0
FN = 0

# manual test cause deeppavlov has bug with test & validation

test_lines = linecache.getlines("./subpool_dpp_"+cur_eco+"/test.csv")
for oneline in tqdm(test_lines[1:]):
    try:
        curlabel = str(oneline).split(',')[1].strip()
        curtokens = str(oneline).split(',')[0].strip()
        curresult = model([curtokens])[0]
        if curlabel!='unknown':
            if curresult!='unknown':
                TP+=1
            else:
                FP+=1
        else:
            if curresult != 'unknown':
                FN += 1
            else:
                TN += 1
    except:
        continue

ACC = (TP+TN)/(TP+FN+FP+TN)
PRE = TP/(TP+FP)
REC = TP/(TP+FN)
F1 = (2*PRE*REC)/(PRE+REC)

print('ACC: ', ACC)
print('precision: ', PRE)
print('recall: ', REC)
print('F1: ', F1)

