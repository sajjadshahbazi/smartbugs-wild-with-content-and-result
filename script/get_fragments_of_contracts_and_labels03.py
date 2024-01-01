
import os
import json
from itertools import chain

import pandas as pd
import re

from gensim.models import Word2Vec

from script.embeding_word_04 import get_fragments, get_tokens

# Sample Solidity contracts and labels (replace with your data)
ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), '..'))
path = f"{ROOT}\\contract\\"  # temp data set
# path = f"{ROOT}\\contracts\\"  # main data set

safe_count = 0
vul_count = 0

labels = []
contracts = []
contracts_vector = []
output_name = 'icse20'
duration_stat = {}
count = {}
output = {}
tools = ['mythril', 'slither', 'osiris', 'smartcheck', 'manticore', 'maian', 'securify', 'honeybadger']  # all tools

target_vulnerability_integer_overflow = 'Integer Overflow' # sum safe smart contract: 28953, sum vulnarable smart contract: 18445
target_vulnerability_reentrancy = 'Reentrancy' # sum safe smart contract: 38423, sum vulnarable smart contract: 8975
target_vulnerability_transaction_order_dependence = 'Transaction order dependence' # sum safe smart contract: 45380, sum vulnarable smart contract: 2018
target_vulnerability_timestamp_dependency = 'timestamp' # sum safe smart contract: 45322 , sum vulnarable smart contract: 2076
target_vulnerability_callstack_depth_attack = 'Transaction Order Dependenc' # sum safe smart contract: 45380 , sum vulnarable smart contract: 2018
target_vulnerability_integer_underflow = 'Integer Underflow' #sum safe smart contract: 43727 , sum vulnarable smart contract: 3671

count = {}
output = {}

os.chdir(path)


def count_dimensions(my_list):
    if not isinstance(my_list, list):
        return 0

    # اگر لیست داخلی وجود داشته باشد، تعداد ابعاد را افزایش می‌دهیم
    inner_dimensions = [count_dimensions(item) for item in my_list if isinstance(item, list)]

    if not inner_dimensions:
        return 1  # لیست یک بعدی
    else:
        return 1 + max(inner_dimensions)


def make_vector(contractss):
    print("rrrrr","01",count_dimensions(contractss))
    # list_1d = list(chain(*contractss))
    # for contra in contractss:
    #     model = Word2Vec(contra, vector_size=300, window=5, min_count=1, sg=0)

    # model = Word2Vec(list_1d, vector_size=300, window=5, min_count=1, sg=0)
    # print("rrrrr", "02", count_dimensions(list_1d))
    # print("rrrrr", "03", len(token))

    for contrac in contractss:
        # text = ', '.join(map(str, contrac))
        model = Word2Vec(contrac, vector_size=300, window=5, min_count=1, sg=0)
        # cont = list(chain(*contrac))
        print("rrrrr", "04", count_dimensions(contrac))
        text = ', '.join(map(str, contrac))
        # print("rrr", text)
        vec = model.wv[contrac]
        print("rrrrr", "05", vec)
        contracts_vector.append(vec)
    print("rrrrr", "06", len(contracts_vector))
    return contracts_vector


def is_sentence_in_text(sentence, text):
    sentence = sentence.lower()
    text = text.lower()
    text = re.sub(r'[^a-z ]', '', text)
    flg = sentence in text
    # print(flg)

    return flg

def getResultVulnarable(contract, target_vulnerability):
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
                        if is_sentence_in_text(target_vulnerability, vulnerability):
                            res = True

            elif tool == 'oyente' or tool == 'osiris' or tool == 'honeybadger':
                for analysis in data['analysis']:
                    if analysis['errors'] is not None:
                        for result in analysis['errors']:
                            vulnerability = result['message'].strip()
                            if is_sentence_in_text(target_vulnerability, vulnerability):
                                res = True

            elif tool == 'manticore':
                for analysis in data['analysis']:
                    for result in analysis:
                        vulnerability = result['name'].strip()
                        if is_sentence_in_text(target_vulnerability, vulnerability):
                            res = True

            elif tool == 'maian':
                for vulnerability in data['analysis']:
                    if data['analysis'][vulnerability]:
                        if is_sentence_in_text(target_vulnerability, vulnerability):
                            res = True

            elif tool == 'securify':
                for f in data['analysis']:
                    analysis = data['analysis'][f]['results']
                    for vulnerability in analysis:
                        for line in analysis[vulnerability]['violations']:
                            if is_sentence_in_text(target_vulnerability, vulnerability):
                                res = True

            elif tool == 'slither':
                analysis = data['analysis']
                for result in analysis:
                    vulnerability = result['check'].strip()
                    line = None
                    if 'source_mapping' in result['elements'][0] and len(
                            result['elements'][0]['source_mapping']['lines']) > 0:
                        line = result['elements'][0]['source_mapping']['lines'][0]
                    if is_sentence_in_text(target_vulnerability, vulnerability):
                        res = True
            elif tool == 'smartcheck':
                analysis = data['analysis']
                for result in analysis:
                    vulnerability = result['name'].strip()
                    if is_sentence_in_text(target_vulnerability, vulnerability):
                        res = True
            elif tool == 'solhint':
                analysis = data['analysis']
                for result in analysis:
                    vulnerability = result['type'].strip()
                    if is_sentence_in_text(target_vulnerability, vulnerability):
                        res = True
    return res


# def make_file():
def make_file(contractsss, labelss):
    # print("----->", len(contractss[0]))
    num_columns = len(contractsss[0])

    print("print 01",len(contractsss[0]))
    print("print 02",len(contractsss[1]))
    print("print 03",len(contractsss[2]))
    print("print 04",len(contractsss[3]))

    df = pd.DataFrame(contractsss)

    df.insert(0, "ردیف", range(1, len(df) + 1))

    df[num_columns + 1] = labelss

    excel_file = f"{ROOT}\script\\Integer_overflow.xlsx"
    # print(excel_file)
    df.to_excel(excel_file, index=False, header=False)

    print("Success !")


def preprocess_contract(contract):
    # Remove the solidity version pragma
    contract = re.sub(r'pragma\s+solidity\s+\^?\d+\.\d+\.\d+;', '', contract)
    # Remove every line containing 'pragma solidity'
    contract = re.sub(r'^\s*pragma\s+solidity\s+.*\n', '\n', contract, flags=re.MULTILINE)
    # Remove blank lines and lines with only spaces
    contract = re.sub(r'(?:(?:\r\n|\r|\n)\s*){2,}', '\n', contract)
    # Remove comments and non-ASCII characters
    contract = re.sub(r'\/\/[^\n]*|\/\*[\s\S]*?\*\/|[^ -~]', ' ', contract)
    return contract


def read_text_file(file_path, name, target_vulnerability):
    with open(file_path, encoding="utf8") as f:
        smartContractContent = f.read()
        isVulnarable = getResultVulnarable(name, target_vulnerability)

        # get fragments
        fragments = get_fragments(smartContractContent)
        # get tokens
        tokens = get_tokens(fragments)

        # print("fragments", fragments)
        # print("tokens", tokens)
        # print("==========> isVulnarable", isVulnarable)

        contracts.append(tokens)
        # print("contracts", contracts)

        isVal = 0
        if (isVulnarable):
            isVal = 1

        labels.append(isVal)
        return isVulnarable


if __name__ == '__main__':
    print("MAKE EXCEL FILE")
    for sss in ["1"]:
        for file in os.listdir():
            # Check whether file is in text format or not
            if file.endswith(".sol"):
                file_path = f"{path}\{file}"
                name = file.replace(".sol", "")

                # set type vulnerability
                target_vulner = target_vulnerability_integer_overflow

                if (read_text_file(file_path, name, target_vulner)):
                    vul_count += 1
                else:
                    safe_count += 1
print("target_vulnerability:", target_vulner)
print(f"sum safe smart contract: {safe_count}", ",", f"sum vulnarable smart contract: {vul_count}")
print('======>> '.join(tools))
# rels: make_vector(contracts)
make_file(make_vector(contracts), labels)
