
# Import Module
import os
import json
import sys
import operator
from datetime import timedelta
from pre_proccessing import runTasks
from gensim.models import Word2Vec

safe_count = 0
vul_count = 0
  
# Folder Path
ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), '..'))
path = f"{ROOT}\\contract\\" # temp data set
# path = f"{ROOT}\\contracts\\" # main data set
  
# Change the directorygrdf
os.chdir(path)
  
def read_text_file(file_path, name):
    with open(file_path, encoding="utf8") as f:
        print("######################################################################################")
        smartContractContent = f.read()
        words = runTasks(smartContractContent)
        # Example: Accessing word embeddings
        print(words)
        model = Word2Vec([words], vector_size=100, window=5, min_count=1, sg=0)
        print(model.wv.vectors)

        print("######################################################################################")
        print(name)
        # print(smartContractContent)
        isVulnarable = gerResultVulnarable(name)
        print(isVulnarable)
        print("======================================================================================")
        return isVulnarable
            
        

output_name = 'icse20'
duration_stat = {}

count = {}
output = {}
# tools = ['mythril','slither','osiris','smartcheck','manticore','maian','securify', 'honeybadger'] 
# if you want show result of tools, you most put name tools in the list
tools = ['mythril','securify','maian','manticore', 'osiris', 'honeybadger']
# tools = ['mythril','securify','smartcheck','smartcheck','manticore','smartcheck']

def gerResultVulnarable(contract):
        total_duration = 0
        res = False
        for tool in tools:
            path_result = os.path.join(f"{ROOT}\\results\\", tool, output_name, contract, 'result.json')
            if not os.path.exists(path_result):
                continue
            with open(path_result, 'r', encoding='utf-8') as fd:
                data = None
                try:
                    data = json.load(fd)
                except Exception as a:
                    continue
                if tool not in duration_stat:
                    duration_stat[tool] = 0
                if tool not in count:
                    count[tool] = 0
                count[tool] += 1
                duration_stat[tool] += data['duration']
                total_duration += data['duration']

                if contract not in output:
                    output[contract] = {
                        'tools': {},
                        'lines': set(),
                        'nb_vulnerabilities': 0
                    }
                output[contract]['tools'][tool] = {
                    'vulnerabilities': {},
                    'categories': {}
                }
                if data['analysis'] is None:
                    continue
                if tool == 'mythril':
                    analysis = data['analysis']
                    if analysis['issues'] is not None:
                        for result in analysis['issues']:
                            vulnerability = result['title'].strip()
                            res = True
                elif tool == 'oyente' or tool == 'osiris':
                    for analysis in data['analysis']:
                        if analysis['errors'] is not None:
                            for result in analysis['errors']:
                                vulnerability = result['message'].strip()
                                res = True
                elif tool == 'manticore':
                    for analysis in data['analysis']:
                        for result in analysis:
                            vulnerability = result['name'].strip()
                            res = True
                elif tool == 'maian':
                    for vulnerability in data['analysis']:
                        if data['analysis'][vulnerability]:
                            res = True
                elif tool == 'securify':
                    for f in data['analysis']:
                        analysis = data['analysis'][f]['results']
                        for vulnerability in analysis:
                            for line in analysis[vulnerability]['violations']:
                                res = True
                elif tool == 'slither':
                    analysis = data['analysis']
                    for result in analysis:
                        vulnerability = result['check'].strip()
                        line = None
                        if 'source_mapping' in result['elements'][0] and len(result['elements'][0]['source_mapping']['lines']) > 0:
                            line = result['elements'][0]['source_mapping']['lines'][0] 
                            res = True
                elif tool == 'smartcheck':
                    analysis = data['analysis']
                    for result in analysis:
                        vulnerability = result['name'].strip()
                        res = True
                elif tool == 'solhint':
                    analysis = data['analysis']
                    for result in analysis:
                        vulnerability = result['type'].strip()
                        res = True
                elif tool == 'honeybadger':
                    for analysis in data['analysis']:
                        if analysis['errors'] is not None:
                            for result in analysis['errors']:
                                vulnerability = result['message'].strip()
                                res = True
        return res


# iterate through all file
for sss in ["1"]:
    for file in os.listdir():
        # Check whether file is in text format or not
        if file.endswith(".sol"):
            file_path = f"{path}\{file}"
            name = file.replace(".sol","")

            # call read text file function
            if(read_text_file(file_path, name)):
                vul_count += 1
            else : 
                safe_count += 1

print(f"sum safe smart contract: {safe_count}")
print(f"sum vulnarable smart contract: {vul_count}")
print('======>> '.join(tools))


