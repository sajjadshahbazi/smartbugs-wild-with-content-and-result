
# Import Module
import os
import json
import re
import sys
import operator
from datetime import timedelta
from pre_proccessing import run_tasks
from pre_proccessing import run_takes01
from pre_proccessing import run_task02
from gensim.models import Word2Vec
from tokeniz import get_vec

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
        # words = get_vec(smartContractContent)
        # words = run_takes01(smartContractContent)
        words = preprocess_contract3(smartContractContent)
        # words = run_tasks(smartContractContent)
        # words = run_task02(smartContractContent)
        # Example: Accessing word embeddings
        print(words)
        # model = Word2Vec([words], vector_size=100, window=5, min_count=1, sg=0)
        # print(model.wv.vectors)
        # print(parse_file(words))
        # print(words)
        print(name)
        print(smartContractContent)
        isVulnarable = gerResultVulnarable(name)
        # print(isVulnarable)
        print("######################################################################################")

        # print("======================================================================================")
        return isVulnarable
            
        

output_name = 'icse20'
duration_stat = {}

count = {}
output = {}
# tools = ['mythril','slither','osiris','smartcheck','manticore','maian','securify', 'honeybadger'] # all tools
# if you want show result of tools, you most put name tools in the list
# tools = ['mythril','securify','maian','manticore', 'osiris', 'honeybadger'] # sum safe smart contract: 10000, sum vulnarable smart contract: 35000
# tools = ['smartcheck','slither'] #sum safe smart contract: 110, sum vulnarable smart contract: 47288
# tools = ['slither'] #sum safe smart contract: 6710, sum vulnarable smart contract: 40688
#tools = ['smartcheck'] #sum safe smart contract: 126, sum vulnarable smart contract: 47272
tools = ['mythril','securify','maian','manticore', 'honeybadger'] #sum safe smart contract: 12618, sum vulnarable smart contract: 34780


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


def parse_file(contract):
    fragment = []
    fragment_val = 0
    for line in contract:
        stripped = line.strip()
        if not stripped:
            continue
        if "-" * 33 in line and fragment:
            yield fragment, fragment_val
            fragment = []
        elif stripped.split()[0].isdigit():
            if fragment:
                if stripped.isdigit():
                    fragment_val = int(stripped)
                else:
                    fragment.append(stripped)
        else:
            fragment.append(stripped)


def preprocess_contract3(solidity_code):
    # 1. Remove Solidity version pragma
    solidity_code = re.sub(r'pragma solidity\s+\^?\d+\.\d+\.\d+;', '', solidity_code)

    # 2. Remove comments and non-ASCII values
    solidity_code = re.sub(r'\/\/[^\n]*|\/\*[\s\S]*?\*\/|[^ -~]', ' ', solidity_code)

    # 3. Remove blank lines
    solidity_code = '\n'.join(line for line in solidity_code.split('\n') if line.strip())

    # 4. Remove lines that just consist of spaces
    solidity_code = '\n'.join(line for line in solidity_code.split('\n') if not line.isspace())

    # 5. Remove the first spaces before sentences on each line
    solidity_code = re.sub(r'^\s+', '', solidity_code, flags=re.MULTILINE)

    # 6. Represent user-defined function names as FUN plus numbers
    function_names = re.findall(r'function\s+(\w+)\s*\(', solidity_code)
    function_name_mapping = {}
    for i, name in enumerate(function_names):
        function_name_mapping[name] = f'FUN{i}'
    for name, replacement in function_name_mapping.items():
        solidity_code = re.sub(f'function\\s+{name}\\b', f'function {replacement}', solidity_code)

    # 7. Represent user-defined variable names as VAR plus numbers
    variable_names = re.findall(r'\bvar\s+(\w+)\s*;', solidity_code)
    variable_name_mapping = {}
    for i, name in enumerate(variable_names):
        variable_name_mapping[name] = f'VAR{i}'
    for name, replacement in variable_name_mapping.items():
        solidity_code = re.sub(f'\\bvar\\s+{name}\\s*;', f'var {replacement};', solidity_code)

    # Print the processed Solidity code
    # print(solidity_code)

    # Extract words from the processed Solidity code
    words = re.findall(r'\b\w+\b', solidity_code)
    return words


def preprocess_contract2(contract):
    # Remove the solidity version pragma
    contract = re.sub(r'pragma\s+solidity\s+\^?\d+\.\d+\.\d+;', '', contract)
    # Remove every line containing 'pragma solidity'
    contract = re.sub(r'^\s*pragma\s+solidity\s+.*\n', '\n', contract, flags=re.MULTILINE)
    # Remove blank lines and lines with only spaces
    contract = re.sub(r'(?:(?:\r\n|\r|\n)\s*){2,}', '\n', contract)
    # Remove comments and non-ASCII characters
    contract_text = re.sub(r'//.*?\n|/\*.*?\*/', '', contract, flags=re.S)

    # Remove non-ASCII characters
    contract_text = ''.join(char for char in contract_text if ord(char) < 128)
    return contract_text


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


