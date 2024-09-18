import json
import re
import os
import PreProcessToolsTwo


duration_stat = {}
count = {}
output = {}
safe_count = 0
vul_count = 0
labels = []
fragment_contracts = []

output_name = 'icse20'

vulnerability_stat = {
}
tool_stat = {}
tool_category_stat = {}
total_duration = 0
contract_vulnerabilities = {}

vulnerability_mapping = {}

tools = ['mythril', 'slither', 'osiris', 'smartcheck', 'manticore', 'maian', 'securify', 'honeybadger']  # all tools analizer

target_vulnerability_integer_overflow = 'Integer Overflow' # sum safe smart contract: 28953, sum vulnarable smart contract: 18445
target_vulnerability_reentrancy = 'Reentrancy' # sum safe smart contract: 38423, sum vulnarable smart contract: 8975
target_vulnerability_transaction_order_dependence = 'Transaction order dependence' # sum safe smart contract: 45380, sum vulnarable smart contract: 2018
target_vulnerability_timestamp_dependency = 'timestamp' # sum safe smart contract: 45322 , sum vulnarable smart contract: 2076
target_vulnerability_callstack_depth_attack = 'Depth Attack' # sum safe smart contract: 45380 , sum vulnarable smart contract: 2018
target_vulnerability_integer_underflow = 'Integer Underflow' #sum safe smart contract: 43727 , sum vulnarable smart contract: 3671

target_vulner = target_vulnerability_reentrancy

ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), '..'))

vulnerability_fd = open(os.path.join(ROOT, 'metadata', 'vulnerabilities.csv'), 'w', encoding='utf-8')

# PATH = f"{ROOT}\\contracts\\"  # main data set
PATH = f"{ROOT}\\contract\\"  # part of main data set
# PATH = f"{ROOT}\\contra\\"  # one smart contract
os.chdir(PATH)


with open(os.path.join(ROOT, 'metadata', 'vulnerabilities_mapping.csv')) as fd:
    header = fd.readline().strip().split(',')
    line = fd.readline()
    while line:
        v = line.strip().split(',')
        index = -1
        if 'TRUE' in v:
            index = v.index('TRUE')
        elif 'MAYBE' in v:
            index = v.index('MAYBE')
        if index > -1:
            vulnerability_mapping[v[1]] = header[index]
        line = fd.readline()
        print(f" Mapppppp {vulnerability_mapping}")
categories = sorted(list(set(vulnerability_mapping.values())))
categories.remove('Ignore')
categories.remove('Other')
categories.append('Other')

def is_sentence_in_text(sentence, text):
    sentence = sentence.lower()
    text = text.lower()
    text = re.sub(r'[^a-z ]', '', text)
    flg = sentence in text
    # print(flg)

    return flg



def add_vul(contract, tool, vulnerability, line):
    print(f" contract : {contract}, vulnerability :{vulnerability}, tool :{tool}, line : {line}")
    print(f"{vulnerability_mapping}")
    original_vulnerability = vulnerability
    vulnerability = vulnerability.strip().lower().title().replace('_', ' ').replace('.', '').replace('Solidity ',
                                                                                                     '').replace(
        'Potentially ', '')
    vulnerability = re.sub(r' At Instruction .*', '', vulnerability)
    # print(f"add vul :{vulnerability}, line : {line}, tool: {tool}, contract : {contract}")


    category = 'unknown'
    if original_vulnerability in vulnerability_mapping:
        category = vulnerability_mapping[original_vulnerability]
    if category == 'unknown' or category == 'Ignore':
        # print(
        #     f" original_vulnerability = {original_vulnerability} @@@@@@@ vulnerability_mapping : {vulnerability_mapping}")

        # print(f"return {original_vulnerability}, {vulnerability} ,{vulnerability_mapping}")
        return
    if vulnerability not in vulnerability_stat:
        vulnerability_stat[vulnerability] = 0
    if tool not in tool_stat:
        tool_stat[tool] = {}
    if vulnerability not in tool_stat[tool]:
        tool_stat[tool][vulnerability] = 0
        vulnerability_fd.write("%s,%s\n" % (tool, original_vulnerability))

    if contract not in contract_vulnerabilities:
        contract_vulnerabilities[contract] = set()

    if vulnerability not in contract_vulnerabilities[contract]:
        vulnerability_stat[vulnerability] += 1
        tool_stat[tool][vulnerability] += 1
        contract_vulnerabilities[contract].add(vulnerability)

    output[contract]['nb_vulnerabilities'] += 1
    if line is not None and line > 0:
        output[contract]['lines'].add(line)
    if original_vulnerability not in output[contract]['tools'][tool]['vulnerabilities']:
        output[contract]['tools'][tool]['vulnerabilities'][original_vulnerability] = 0
    output[contract]['tools'][tool]['vulnerabilities'][original_vulnerability] += 1

    if category not in output[contract]['tools'][tool]['categories']:
        output[contract]['tools'][tool]['categories'][category] = 0
    output[contract]['tools'][tool]['categories'][category] += 1

    if tool not in tool_category_stat:
        tool_category_stat[tool] = {}
    if category not in tool_category_stat[tool]:
        tool_category_stat[tool][category] = set()
    vuln = contract
    tool_category_stat[tool][category].add(vuln)

    # print(f"end add vul :|{tool_category_stat}| {vulnerability}")




total_duration = 0
index = 0
nb_contract = 0
def getResultVulnarable(contract_name, target_vulnerability):
    total_duration = 0
    res = False
#     for tool in tools:
#         path_result = os.path.join(f"{ROOT}\\results\\", tool, output_name, contract_name, 'result.json')
#         if not os.path.exists(path_result):
#             continue
#         with open(path_result, 'r', encoding='utf-8') as fd:
#             data = None
#             try:
#                 data = json.load(fd)
#             except Exception as a:
#                 continue
#             if tool not in duration_stat:
#                 duration_stat[tool] = 0
#             if tool not in count:
#                 count[tool] = 0
#             count[tool] += 1
#             duration_stat[tool] += data['duration']
#             total_duration += data['duration']
# with open(os.path.join(ROOT, 'metadata', 'unique_contracts.csv')) as ufd:
#     line = ufd.readline()
#     while line:
#         contract = line.split(',')[0]
#         index += 1
    for tool in tools:
        path_result = os.path.join(f"{ROOT}\\results\\", tool, output_name, contract_name, 'result.json')
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

            if contract_name not in output:
                output[contract_name] = {
                    'tools': {},
                    'lines': set(),
                    'nb_vulnerabilities': 0
                }
            output[contract_name]['tools'][tool] = {
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
                        add_vul(contract_name, tool, vulnerability, result['lineno'])
            elif tool == 'oyente' or tool == 'osiris' or tool == 'honeybadger':
                for analysis in data['analysis']:
                    if analysis['errors'] is not None:
                        for result in analysis['errors']:
                            vulnerability = result['message'].strip()
                            add_vul(contract_name, tool, vulnerability, result['line'])
            elif tool == 'manticore':
                for analysis in data['analysis']:
                    for result in analysis:
                        vulnerability = result['name'].strip()
                        add_vul(contract_name, tool, vulnerability, result['line'])
            elif tool == 'maian':
                for vulnerability in data['analysis']:
                    if data['analysis'][vulnerability]:
                        add_vul(contract_name, tool, vulnerability, None)
            elif tool == 'securify':
                for f in data['analysis']:
                    analysis = data['analysis'][f]['results']
                    for vulnerability in analysis:
                        for line in analysis[vulnerability]['violations']:
                            add_vul(contract_name, tool, vulnerability, line + 1)
            elif tool == 'slither':
                analysis = data['analysis']
                for result in analysis:
                    vulnerability = result['check'].strip()
                    line = None
                    if 'source_mapping' in result['elements'][0] and len(
                            result['elements'][0]['source_mapping']['lines']) > 0:
                        line = result['elements'][0]['source_mapping']['lines'][0]
                    add_vul(contract_name, tool, vulnerability, line)
            elif tool == 'smartcheck':
                analysis = data['analysis']
                for result in analysis:
                    vulnerability = result['name'].strip()
                    add_vul(contract_name, tool, vulnerability, result['line'])
            elif tool == 'solhint':
                analysis = data['analysis']
                for result in analysis:
                    vulnerability = result['type'].strip()
                    add_vul(contract_name, tool, vulnerability, int(result['line']))
    # line = ufd.readline()








def getResultVulnarablee(contract_name, target_vulnerability):
    total_duration = 0
    res = False
    for tool in tools:
        path_result = os.path.join(f"{ROOT}\\results\\", tool, output_name, contract_name, 'result.json')
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

            if contract_name not in output:
                output[contract_name] = {
                    'tools': {},
                    'lines': set(),
                    'nb_vulnerabilities': 0
                }
            output[contract_name]['tools'][tool] = {
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



def main(file_path, name, target_vulnerability):
    with open(file_path, encoding="utf8") as f:
        smartContractContent = f.read()
        isVulnarable = getResultVulnarable(name, target_vulnerability)

        # get fragments
        fragments = PreProcessToolsTwo.get_fragments(smartContractContent)
        # for frag in fragments:
        #     print(f"{frag}")


        fragment_contracts.append(fragments)

        isVal = 0
        if (isVulnarable):
            isVal = 1

        labels.append(isVal)
        return isVulnarable





if __name__ == "__main__":
    for file in os.listdir():
        # Check whether file is in text format or not
        if file.endswith(".sol"):
            file_path = f"{PATH}\{file}"
            name = file.replace(".sol", "")

            # set type vulnerability
            target_vulner = target_vulnerability_integer_overflow

            if (main(file_path, name, target_vulner)):
                vul_count += 1
            else:
                safe_count += 1