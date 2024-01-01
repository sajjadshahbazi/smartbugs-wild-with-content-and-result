
import os
import json

import pandas as pd
import re

from sklearn.metrics import precision_score, recall_score, f1_score

import numpy as np
from sklearn.model_selection import train_test_split
from keras.preprocessing.text import Tokenizer
from keras.preprocessing.sequence import pad_sequences
from keras.models import Sequential
from keras.layers import Embedding, LSTM, Dense

from script.embeding_word_04 import get_fragments, get_tokens

# Sample Solidity contracts and labels (replace with your data)
ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), '..'))
# path = f"{ROOT}\\contract\\"  # temp data set
path = f"{ROOT}\\contracts\\"  # main data set

safe_count = 0
vul_count = 0

labels = []
contracts = []
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



def run_process(contractsss, labelss):
    # Example label(0 for safe, 1 for vulnerable)
    # contractsss = [preprocess_contract(contract) for contract in contractss]

    # print(contractsss)
    # print(labelss)

    # 2. Tokenization and Vectorization
    max_words = 10000  # Define the maximum number of words in your vocabulary
    tokenizer = Tokenizer(num_words=max_words, char_level=True)
    tokenizer.fit_on_texts(contractsss)
    sequences = tokenizer.texts_to_sequences(contractsss)

    # 3. Sequence Padding
    max_sequence_length = 1000  # Choose an appropriate sequence length
    data = pad_sequences(sequences, maxlen=max_sequence_length)

    # 4. Split the data into training and testing sets
    X_train, X_test, y_train, y_test = train_test_split(data, labelss, test_size=0.2, random_state=42)

    # 5. LSTM Model
    model = Sequential()
    model.add(Embedding(input_dim=max_words, output_dim=100, input_length=max_sequence_length))
    model.add(LSTM(100))
    model.add(Dense(1, activation='sigmoid'))

    model.compile(loss='binary_crossentropy', optimizer='adam', metrics=['accuracy'])

    X_train = np.array(X_train)
    X_test = np.array(X_test)
    y_test = np.array(y_test)
    y_train = np.array(y_train)

    # 6. Model Training
    model.fit(X_train, y_train, epochs=10, batch_size=64, validation_data=(X_test, y_test))

    # 7. Model Evaluation
    loss, accuracy = model.evaluate(X_test, y_test)

    y_pred = model.predict(X_test)

    print(f'Test loss: {loss}')
    print(f'Test accuracy: {accuracy}')

    precision = precision_score(y_test, (y_pred > 0.5).astype(int))
    recall = recall_score(y_test, (y_pred > 0.5).astype(int))
    f1 = f1_score(y_test, (y_pred > 0.5).astype(int))

    print(f'Precision: {precision}')
    print(f'Recall: {recall}')
    print(f'F1-Score: {f1}')

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
def make_file(contractss, labelss):
    print("----->", len(contractss[0]))
    num_columns = len(contractss[0])

    df = pd.DataFrame(contractss)

    df.insert(0, "ردیف", range(1, len(df) + 1))

    df[num_columns + 1] = labelss

    excel_file = f"{ROOT}\script\\Integer_overflow.xlsx"
    print(excel_file)
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
        # # get tokens
        # tokens = get_tokens(fragments)
        #
        # print("fragments", fragments)
        # print("tokens", tokens)
        # print("==========> isVulnarable", isVulnarable)

        contracts.append(fragments)
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
                target_vulner = target_vulnerability_timestamp_dependency

                if (read_text_file(file_path, name, target_vulner)):
                    vul_count += 1
                else:
                    safe_count += 1
print("target_vulnerability:", target_vulner)
print(f"sum safe smart contract: {safe_count}", ",", f"sum vulnarable smart contract: {vul_count}")
print('======>> '.join(tools))
run_process(contracts, labels)
