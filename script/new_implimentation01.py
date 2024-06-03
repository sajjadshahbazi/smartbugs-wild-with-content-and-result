
import os
import json
import numpy as np
import re

from gensim.models import Word2Vec

ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), '..'))
path = f"{ROOT}\\contracts\\"  # main data set
vector_length=1500
safe_count = 0
vul_count = 0

os.chdir(path)

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
target_vulnerability_callstack_depth_attack = 'Depth Attack' # sum safe smart contract: 45380 , sum vulnarable smart contract: 2018
target_vulnerability_integer_underflow = 'Integer Underflow' #sum safe smart contract: 43727 , sum vulnarable smart contract: 3671

target_vulner = target_vulnerability_reentrancy

main_args = frozenset({'argc', 'argv'})

keywords = frozenset(
    {'bool', 'break', 'case', 'catch', 'const', 'continue', 'default', 'do', 'double', 'struct',
     'else', 'enum', 'payable', 'function', 'modifier', 'emit', 'export', 'extern', 'false', 'constructor',
     'float', 'if', 'contract', 'int', 'long', 'string', 'super', 'or', 'private', 'protected', 'noReentrancy',
     'public', 'return', 'returns', 'assert', 'event', 'indexed', 'using', 'require', 'uint', 'onlyDaoChallenge',
     'transfer', 'Transfer', 'Transaction', 'switch', 'pure', 'view', 'this', 'throw', 'true', 'try', 'revert',
     'bytes', 'bytes4', 'bytes32', 'internal', 'external', 'union', 'constant', 'while', 'for', 'notExecuted',
     'NULL', 'uint256', 'uint128', 'uint8', 'uint16', 'address', 'call', 'msg', 'value', 'sender', 'notConfirmed',
     'private', 'onlyOwner', 'internal', 'onlyGovernor', 'onlyCommittee', 'onlyAdmin', 'onlyPlayers', 'ownerExists',
     'onlyManager', 'onlyHuman', 'only_owner', 'onlyCongressMembers', 'preventReentry', 'noEther', 'onlyMembers',
     'onlyProxyOwner', 'confirmed', 'mapping'})

# holds known non-user-defined functions; immutable set
main_set = frozenset({'function', 'constructor', 'modifier', 'contract'})

operators3 = {'<<=', '>>='}
operators2 = {
    '->', '++', '--',
    '!~', '<<', '>>', '<=', '>=',
    '==', '!=', '&&', '||', '+=',
    '-=', '*=', '/=', '%=', '&=', '^=', '|='
}
operators1 = {
    '(', ')', '[', ']', '.',
    '+', '-', '*', '&', '/',
    '%', '<', '>', '^', '|',
    '=', ',', '?', ':', ';',
    '{', '}'
}




@staticmethod
def tokenize(line):
    tmp, w = [], []
    i = 0
    while i < len(line):
        # Ignore spaces and combine previously collected chars to form words
        if line[i] == ' ':
            tmp.append(''.join(w))
            tmp.append(line[i])
            w = []
            i += 1
        # Check operators and append to final list
        elif line[i:i + 3] in operators3:
            tmp.append(''.join(w))
            tmp.append(line[i:i + 3])
            w = []
            i += 3
        elif line[i:i + 2] in operators2:
            tmp.append(''.join(w))
            tmp.append(line[i:i + 2])
            w = []
            i += 2
        elif line[i] in operators1:
            tmp.append(''.join(w))
            tmp.append(line[i])
            w = []
            i += 1
        # Character appended to word list
        else:
            w.append(line[i])
            i += 1
    # Filter out irrelevant strings
    res = list(filter(lambda c: c != '', tmp))
    return list(filter(lambda c: c != ' ', res))

def clean_fragment(fragment):
    # dictionary; map function name to symbol name + number
    fun_symbols = {}
    # dictionary; map variable name to symbol name + number
    var_symbols = {}

    fun_count = 1
    var_count = 1

    # regular expression to catch multi-line comment
    rx_comment = re.compile('\*/\s*$')
    # regular expression to find function name candidates
    rx_fun = re.compile(r'\b([_A-Za-z]\w*)\b(?=\s*\()')
    # regular expression to find variable name candidates
    # rx_var = re.compile(r'\b([_A-Za-z]\w*)\b(?!\s*\()')
    rx_var = re.compile(r'\b([_A-Za-z]\w*)\b(?:(?=\s*\w+\()|(?!\s*\w+))(?!\s*\()')

    # final cleaned gadget output to return to interface
    cleaned_fragment = []

    for line in fragment:
        # process if not the header line and not a multi-line commented line
        if rx_comment.search(line) is None:
            # remove all string literals (keep the quotes)
            nostrlit_line = re.sub(r'".*?"', '""', line)
            # remove all character literals
            nocharlit_line = re.sub(r"'.*?'", "''", nostrlit_line)
            # replace any non-ASCII characters with empty string
            ascii_line = re.sub(r'[^\x00-\x7f]', r'', nocharlit_line)

            # return, in order, all regex matches at string list; preserves order for semantics
            user_fun = rx_fun.findall(ascii_line)
            user_var = rx_var.findall(ascii_line)

            # Could easily make a "clean fragment" type class to prevent duplicate functionality
            # of creating/comparing symbol names for functions and variables in much the same way.
            # The comparison frozenset, symbol dictionaries, and counters would be class scope.
            # So would only need to pass a string list and a string literal for symbol names to
            # another function.
            for fun_name in user_fun:
                if len({fun_name}.difference(main_set)) != 0 and len({fun_name}.difference(keywords)) != 0:
                    # DEBUG
                    # print('comparing ' + str(fun_name + ' to ' + str(main_set)))
                    # print(fun_name + ' diff len from main is ' + str(len({fun_name}.difference(main_set))))
                    # print('comparing ' + str(fun_name + ' to ' + str(keywords)))
                    # print(fun_name + ' diff len from keywords is ' + str(len({fun_name}.difference(keywords))))
                    ###
                    # check to see if function name already in dictionary
                    if fun_name not in fun_symbols.keys():
                        fun_symbols[fun_name] = 'FUN' + str(fun_count)
                        fun_count += 1
                    # ensure that only function name gets replaced (no variable name with same
                    # identifier); uses positive lookforward
                    ascii_line = re.sub(r'\b(' + fun_name + r')\b(?=\s*\()', fun_symbols[fun_name], ascii_line)

            for var_name in user_var:
                # next line is the nuanced difference between fun_name and var_name
                if len({var_name}.difference(keywords)) != 0 and len({var_name}.difference(main_args)) != 0:
                    # DEBUG
                    # print('comparing ' + str(var_name + ' to ' + str(keywords)))
                    # print(var_name + ' diff len from keywords is ' + str(len({var_name}.difference(keywords))))
                    # print('comparing ' + str(var_name + ' to ' + str(main_args)))
                    # print(var_name + ' diff len from main args is ' + str(len({var_name}.difference(main_args))))
                    ###
                    # check to see if variable name already in dictionary
                    if var_name not in var_symbols.keys():
                        var_symbols[var_name] = 'VAR' + str(var_count)
                        var_count += 1
                    # ensure that only variable name gets replaced (no function name with same
                    # identifier; uses negative lookforward
                    ascii_line = re.sub(r'\b(' + var_name + r')\b(?:(?=\s*\w+\()|(?!\s*\w+))(?!\s*\()', \
                                        var_symbols[var_name], ascii_line)

            cleaned_fragment.append(ascii_line)
    # return the list of cleaned lines
    return cleaned_fragment

def get_tokens_string(fragments):
    tokens = []
    for fragment in fragments:
        frg = tokenize(fragment)
        frg.append("space")
        tokens.append(frg)

    # print(f"token {tokens}")
    return tokens

def is_sentence_in_text(sentence, text):
    sentence = sentence.lower()
    text = text.lower()
    text = re.sub(r'[^a-z ]', '', text)
    flg = sentence in text
    # print(flg)

    return flg


def remove_version(contract_text):
    # Remove solidity version pragma
    res = re.sub(r'pragma solidity\s+\^?\d+\.\d+\.\d+;', '', contract_text)
    res = '\n'.join([line for line in res.split('\n') if 'pragma solidity' not in line])
    return res


def remove_black_lines(contract):
    solidity_code = '\n'.join([line for line in contract.split('\n') if line.strip() != ''])
    solidity_code = '\n'.join(line for line in solidity_code.split('\n') if line.strip())
    solidity_code = '\n'.join(line for line in solidity_code.split('\n') if not line.isspace())
    return solidity_code

def remove_comments_and_non_ascii(contract):
    contract = re.sub(r'\/\*[\s\S]*?\*\/|\/\/[^\n]*', '', contract)
    contract = re.sub(r'\/\/.*', '', contract)  # Remove comments
    contract = re.sub(r'[^\x00-\x7F]+', '', contract)
    contract = ''.join([i if ord(i) < 128 else ' ' for i in contract])

    return contract

def remove_begginer_space(contract):
    # Split the text into lines and remove leading spaces
    lines = [line.lstrip() for line in contract.splitlines()]

    # Join the lines back into a single text
    cleaned_text = '\n'.join(lines)
    return cleaned_text

def get_fragments(contract):
    contract = remove_version(contract)
    contract = remove_comments_and_non_ascii(contract)
    contract = remove_begginer_space(contract)
    contract = remove_black_lines(contract)
    segments = contract.strip().split('\n')
    # print(f"Fragment 01 {segments}")
    fragments = clean_fragment(segments)
    return fragments

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

def read_text_file(file_path, name, target_vulnerability):
    with open(file_path, encoding="utf8") as f:
        smartContractContent = f.read()
        isVulnarable = getResultVulnarable(name, target_vulnerability)

        # get fragments
        fragment = get_fragments(smartContractContent)
        # print(f"Fragment ====> {fragment}")
        # get tokens
        tokens = get_tokens_string(fragment)
        # print(f"tokens ====> {tokens}")
        contracts.append(tokens)

        isVal = 0
        if (isVulnarable):
            isVal = 1

        labels.append(isVal)
        return isVulnarable


def make_vector(tokenize_contracts: list):
    # تبدیل لیست سه بعدی به لیست از لیست‌های کلمات
    all_tokens = []
    # print(f"vectore")
    for sublist1 in tokenize_contracts:
        for sublist2 in sublist1:
            all_tokens.extend(sublist2)
    # ایجاد مدل Word2Vec
    w2v_model = Word2Vec(sentences=all_tokens, vector_size=300, window=10, min_count=5, workers=6)
    # ماتریس‌های متناظر با هر قرارداد
    contract_matrices = []
    for contract in tokenize_contracts:
        contract_matrix = []
        for sublist in contract:
            sublist_matrix = []
            for token in sublist:
                try:
                    vector = w2v_model.wv[token]
                except KeyError:
                    # برای توکن‌های نامعلوم
                    vector = np.zeros(300)
                sublist_matrix.append(vector)
            contract_matrix.append(sublist_matrix)
        contract_matrices.append(contract_matrix)

    return contract_matrices




def get_lenght(cons : list):
    lengths = [len(contract) for contract in cons]

    # محاسبه میانگین، میانه، و سایر آماره‌ها
    mean_length = np.mean(lengths)
    median_length = np.median(lengths)
    max_length = np.max(lengths)
    min_length = np.min(lengths)

    print(f"Average length: {mean_length}")
    print(f"Median length: {median_length}")
    print(f"Max length: {max_length}")
    print(f"Min length: {min_length}")

    # نمایش توزیع طول دنباله‌ها
    import matplotlib.pyplot as plt

    plt.hist(lengths, bins=30)
    plt.title('Distribution of Sequence Lengths')
    plt.xlabel('Sequence Length')
    plt.ylabel('Frequency')
    plt.show()




if __name__ == '__main__':
    print("MAKE EXCEL FILE")
    for file in os.listdir():
        # print(f"MAKE EXCEL FILE 01{file}")
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


vecs = make_vector(contracts)
get_lenght(vecs)
print("target_vulnerability:", target_vulner)
print("vectore: ", vecs)
print(f"sum safe smart contract: {safe_count}", ",", f"sum vulnarable smart contract: {vul_count}")
print('======>> '.join(tools))
