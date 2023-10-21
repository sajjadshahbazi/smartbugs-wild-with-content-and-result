import json
import os
import re
import numpy as np
from keras.preprocessing.text import Tokenizer
from keras.preprocessing.sequence import pad_sequences

ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), '..'))
path = f"{ROOT}\\contract\\" # temp data set
tools = ['mythril','securify','maian','manticore', 'honeybadger']
output_name = 'icse20'
duration_stat = {}
count = {}
output = {}

os.chdir(path)

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
                    if 'source_mapping' in result['elements'][0] and len(
                            result['elements'][0]['source_mapping']['lines']) > 0:
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


# Define a function to preprocess a single smart contract
def preprocess_contract(contract):
    # Task 1: Remove solidity code version
    contract = re.sub(r'pragma solidity[\s\S]*?;', '', contract)

    # Task 2: Remove lines containing pragma solidity
    contract = '\n'.join([line for line in contract.split('\n') if 'pragma solidity' not in line])

    # Task 3: Remove blank lines and lines with only spaces
    contract = '\n'.join([line for line in contract.split('\n') if line.strip() != ''])

    # Task 4: Remove comments and non-ASCII characters
    contract = re.sub(r'\/\*[\s\S]*?\*\/|\/\/[^\n]*', '', contract)
    contract = ''.join([i if ord(i) < 128 else ' ' for i in contract])

    return contract

# Define a function to tokenize and pad a list of contracts
def tokenize_and_pad_contracts(contracts, max_length):
    tokenizer = Tokenizer(filters='', char_level=True)
    tokenizer.fit_on_texts(contracts)
    sequences = tokenizer.texts_to_sequences(contracts)
    data = pad_sequences(sequences, maxlen=max_length)
    return data

# Specify the directory containing the contracts
# contract_dir = 'contracts/'

# Initialize lists to store preprocessed contracts and their lengths
preprocessed_contracts = []
contract_lengths = []

# Task 7: Process each contract
# for filename in os.listdir(contract_dir):
#     with open(os.path.join(contract_dir, filename), 'r', encoding='utf-8') as file:
#         contract = file.read()

def vectorize(preprocessed_contracts):
    preprocessed_contracts = [contract for contract in preprocessed_contracts if contract.strip() != '']

    # Task 6: Replace user-defined function names and variable names
    # with placeholders like FUN1, VAR1, etc.
    function_name_pattern = re.compile(r'function ([a-zA-Z_][a-zA-Z0-9_]*)\s*\(.*\)')
    variable_name_pattern = re.compile(
        r'([a-zA-Z_][a-zA-Z0-9_]*)\s+(public|private|internal|external)\s+(?:view|pure)?\s*(?:constant)?\s*([a-zA-Z_][a-zAZ0-9_]*)\s*=\s*.*;')
    function_count = 1
    variable_count = 1

    for i in range(len(preprocessed_contracts)):
        preprocessed_contracts[i] = function_name_pattern.sub(f'function FUN{function_count}(',
                                                              preprocessed_contracts[i])
        function_count += 1

        preprocessed_contracts[i] = variable_name_pattern.sub(f'VAR{variable_count} =', preprocessed_contracts[i])
        variable_count += 1

    # Task 8: Tokenize and pad contracts
    max_length = max(contract_lengths)
    data = tokenize_and_pad_contracts(preprocessed_contracts, max_length)

    # Task 5 (Again): Remove blank lines from contracts
    preprocessed_contracts = [contract for contract in preprocessed_contracts if contract.strip() != '']
    print(preprocessed_contracts)
    return preprocessed_contracts


for sss in ["1"]:
    print(f"fffffffff : ")
    for file in os.listdir():
        print(f"fffffffff : ")
        # Check whether file is in text format or not
        if file.endswith(".sol"):
            file_path = f"{path}\{file}"
            name = file.replace(".sol", "")
            # read_text_file(file_path, name)
            print(f"fffffffff : ${file_path}")
            with open(file_path, encoding="utf8") as f:
                print("######################################################################################")
                smartContractContent = f.read()
                preprocessed_contract = preprocess_contract(smartContractContent)
                preprocessed_contracts.append(preprocessed_contract)
                contract_lengths.append(len(preprocessed_contract))

            vectorize(preprocessed_contracts)

# Task 5: Remove blank lines from contracts


# Now, 'data' contains the matrix form for deep learning, and 'preprocessed_contracts' contains the preprocessed contracts.