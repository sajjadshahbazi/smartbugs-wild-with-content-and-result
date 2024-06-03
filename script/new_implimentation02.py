

import json
import re
import os
import pandas
import pandas as pd
from clean_fragment import clean_fragment
from vectorize_fragment import FragmentVectorizer
from models.blstm import BLSTM
from models.blstm_attention import BLSTM_Attention
from models.lstm import LSTM_Model
from models.simple_rnn import Simple_RNN
from parser import parameter_parser
duration_stat = {}
count = {}
output = {}



output_name = 'icse20'
tools = ['mythril', 'slither', 'osiris', 'smartcheck', 'manticore', 'maian', 'securify', 'honeybadger']  # all tools
args = parameter_parser()

target_vulnerability_integer_overflow = 'Integer Overflow' # sum safe smart contract: 28953, sum vulnarable smart contract: 18445
target_vulnerability_reentrancy = 'Reentrancy' # sum safe smart contract: 38423, sum vulnarable smart contract: 8975
target_vulnerability_transaction_order_dependence = 'Transaction order dependence' # sum safe smart contract: 45380, sum vulnarable smart contract: 2018
target_vulnerability_timestamp_dependency = 'timestamp' # sum safe smart contract: 45322 , sum vulnarable smart contract: 2076
target_vulnerability_callstack_depth_attack = 'Depth Attack' # sum safe smart contract: 45380 , sum vulnarable smart contract: 2018
target_vulnerability_integer_underflow = 'Integer Underflow' #sum safe smart contract: 43727 , sum vulnarable smart contract: 3671

target_vulner = target_vulnerability_reentrancy

ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), '..'))
PATH = f"{ROOT}\\contracts\\"  # main data set

os.chdir(PATH)

for arg in vars(args):
    print(arg, getattr(args, arg))





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

def minify_solidity_code(code):
    # حذف کامنت‌های چند خطی
    code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
    # حذف کامنت‌های تک خطی
    code = re.sub(r'//.*', '', code)
    # حذف فضاهای اضافی و خطوط جدید بین عبارات، با حفظ رشته‌ها و محتوای داخل آنها
    code = re.sub(r'\s+', ' ', code)  # جایگزینی تمام whitespace ها با یک فضای خالی
    code = re.sub(r'\s*;\s*', ';', code)  # حذف فضاهای اضافی دور نقطه‌ویرگول
    code = re.sub(r'\s*{\s*', '{', code)  # حذف فضاهای اضافی دور کروشه باز
    code = re.sub(r'\s*}\s*', '}', code)  # حذف فضاهای اضافی دور کروشه بسته
    code = re.sub(r'\s*\(\s*', '(', code)  # حذف فضاهای اضافی دور پرانتز باز
    code = re.sub(r'\s*\)\s*', ')', code)  # حذف فضاهای اضافی دور پرانتز بسته
    code = re.sub(r'\s*,\s*', ',', code)  # حذف فضاهای اضافی دور کاما
    return code.strip()

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
    # contract = minify_solidity_code(contract)
    segments = contract.strip().split('\n')
    # print(f"Fragment 01 {segments}")
    fragments = clean_fragment(segments)
    return fragments

def is_sentence_in_text(sentence, text):
    sentence = sentence.lower()
    text = text.lower()
    text = re.sub(r'[^a-z ]', '', text)
    flg = sentence in text
    # print(flg)

    return flg

def getResultVulnarable(contract_name, target_vulnerability):
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



# def parse_file(filename):
#     fragment = []
#     fragment_val = 0
#     if getResultVulnarable(filename, target_vulner):
#         fragment_val = 1
#     else:
#         fragment_val = 0
#     path_file = f"{PATH}{filename}.sol"
#     print(f"Path file :{path_file}")
#     with open(path_file, encoding="utf8") as file:
#         print(f"tgrr :{path_file}, {file}")
#         smartContractContent = file.read()
#         fragment = get_fragments(smartContractContent)
#     return fragment
def parse_file(filename):
    fragment = []
    if getResultVulnarable(filename, target_vulner):
        fragment_val = 1
    else:
        fragment_val = 0
    path_file = f"{PATH}{filename}.sol"
    # print(f"Path file: {path_file}")
    with open(path_file, encoding="utf8") as file:
        smartContractContent = file.read()
        fragments = get_fragments(smartContractContent)  # فرض بر اینکه این تابع لیستی از فرگمنت‌ها برمی‌گرداند
    return [(fragment, fragment_val) for fragment in fragments]




def get_vectors_df(filename, vector_length=300):
    # print(f"get_vectors_df : {filename}")
    fragments = []
    count = 0
    vectorizer = FragmentVectorizer(vector_length)
    for fragment, val in parse_file(filename):
        count += 1
        print("Collecting fragments...", count, end="\r")
        vectorizer.add_fragment(fragment)
        row = {"fragment": fragment, "val": val}
        # print(f"roww {row}")
        fragments.append(row)
    # print('Found {} forward slices and {} backward slices'
    #       .format(vectorizer.forward_slices, vectorizer.backward_slices))

    print("Training model...", end="\r")
    vectorizer.train_model()
    vectors = []
    count = 0
    for fragment in fragments:
        count += 1
        print("Processing fragments...", count, end="\r")
        vector = vectorizer.vectorize(fragment["fragment"])
        row = {"vector": vector, "val": fragment["val"]}
        vectors.append(row)

    df = pandas.DataFrame(vectors)
    return df


def main():

    # base = os.path.splitext(os.path.basename(ROOT))[0]
    # print("01", base)
    vector_filename = ROOT + "_fragment_vectors.pkl"
    print("02", vector_filename)
    vector_length = args.vector_dim
    df: pandas.DataFrame
    # print(f"PATTHHHH {vector_filename}")
    if os.path.exists(vector_filename):
        print("03", vector_filename)
        df = pandas.read_pickle(vector_filename)
    else:
        all_dfs = []  # لیستی برای نگهداری تمام دیتافریم‌ها
        for file in os.listdir():
            # print(f"smart contrct {file}")
            if file.endswith(".sol"):
                file_path = f"{PATH}\{file}"
                name = file.replace(".sol", "")
                df = get_vectors_df(name, vector_length)
                # print("Number of samples in DataFrame:", len(df))
                if df.empty:
                    print("DataFrame is empty. Exiting...")
                    continue
                all_dfs.append(df)

        # تجمیع تمام دیتافریم‌ها به یک دیتافریم واحد
        if all_dfs:
            final_df = pd.concat(all_dfs, ignore_index=True)
            final_df.to_pickle(vector_filename)
            print("All vectors saved to:")
        else:
            print("No data to save.")

    # pd.set_option("display.max_rows", None, "display.max_columns", None)
    # print(df)

    # if args.model == 'BLSTM_Attention':
    #     model = BLSTM_Attention(df, name=base)
    # elif args.model == 'BLSTM':
    #     model = BLSTM(df, name=base)
    # elif args.model == 'Simple_RNN':
    #     model = Simple_RNN(df, name=base)
    # elif args.model == 'LSTM_Model':
    print("Start LSTM !!")
    model = LSTM_Model(df, name=ROOT)
    model.train()
    model.test()


if __name__ == "__main__":
    main()
