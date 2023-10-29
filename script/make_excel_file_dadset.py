import re
import os
import json

import gensim
import pandas as pd
from gensim.models import Word2Vec
from openpyxl import load_workbook

import numpy as np
from sklearn.model_selection import train_test_split
from keras.preprocessing.text import Tokenizer
from keras.preprocessing.sequence import pad_sequences
from keras.models import Sequential
from keras.layers import Embedding, LSTM, Dense
from sklearn.metrics import precision_score, recall_score, f1_score

from script.embeding_word_03 import run_task_04
from script.vectorize_fragment_two import FragmentVectorizer

# Sample Solidity contracts and labels (replace with your data)
ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), '..'))
path = f"{ROOT}\\contract\\" # temp data set
# path = f"{ROOT}\\contracts\\" # main data set

labels = []
contracts = []
output_name = 'icse20'
duration_stat = {}
count = {}
output = {}
tools = ['mythril','slither','osiris','smartcheck','manticore','maian','securify', 'honeybadger'] # all tools
# if you want show result of tools, you most put name tools in the list
# tools = ['mythril','securify','maian','manticore', 'osiris', 'honeybadger'] # sum safe smart contract: 10000, sum vulnarable smart contract: 35000
# tools = ['smartcheck','slither'] #sum safe smart contract: 110, sum vulnarable smart contract: 47288
# tools = ['slither'] #sum safe smart contract: 6710, sum vulnarable smart contract: 40688
#tools = ['smartcheck'] #sum safe smart contract: 126, sum vulnarable smart contract: 47272
# tools = ['mythril','securify','maian','manticore', 'honeybadger'] #sum safe smart contract: 12618, sum vulnarable smart contract: 34780
# tools = ['mythril']  # sum safe smart contract: 24354 sum vulnarable smart contract: 23044
# tools = ['mythril', 'oyente','maian','securify']

target_vulnarable = 'Integer Overflow'
count = {}
output = {}


def vectorize(self, fragment):
    tokenized_fragment, backwards_slice = FragmentVectorizer.tokenize_fragment(fragment)
    vectors = np.zeros(shape=(100, self.vector_length))
    if backwards_slice:
        for i in range(min(len(tokenized_fragment), 100)):
            vectors[100 - 1 - i] = self.embeddings[tokenized_fragment[len(tokenized_fragment) - 1 - i]]
    else:
        for i in range(min(len(tokenized_fragment), 100)):
            vectors[i] = self.embeddings[tokenized_fragment[i]]
    return vectors

def getResultVulnarable(contract):
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
                        if target_vulnarable == vulnerability:
                            res = True
            elif tool == 'oyente' or tool == 'osiris' or tool == 'honeybadger':
                for analysis in data['analysis']:
                    if analysis['errors'] is not None:
                        for result in analysis['errors']:
                            vulnerability = result['message'].strip()
                            if target_vulnarable == vulnerability:
                                res = True
            elif tool == 'manticore':
                for analysis in data['analysis']:
                    for result in analysis:
                        vulnerability = result['name'].strip()
                        if target_vulnarable == vulnerability:
                            res = True
            elif tool == 'maian':
                for vulnerability in data['analysis']:
                    if data['analysis'][vulnerability]:
                        if target_vulnarable == vulnerability:
                            res = True
            elif tool == 'securify':
                for f in data['analysis']:
                    analysis = data['analysis'][f]['results']
                    for vulnerability in analysis:
                        for line in analysis[vulnerability]['violations']:
                            if target_vulnarable == vulnerability:
                                res = True
            elif tool == 'slither':
                analysis = data['analysis']
                for result in analysis:
                    vulnerability = result['check'].strip()
                    line = None
                    if 'source_mapping' in result['elements'][0] and len(
                            result['elements'][0]['source_mapping']['lines']) > 0:
                        line = result['elements'][0]['source_mapping']['lines'][0]
                    if target_vulnarable == vulnerability:
                        res = True
            elif tool == 'smartcheck':
                analysis = data['analysis']
                for result in analysis:
                    vulnerability = result['name'].strip()
                    if target_vulnarable == vulnerability:
                        res = True
            elif tool == 'solhint':
                analysis = data['analysis']
                for result in analysis:
                    vulnerability = result['type'].strip()
                    if target_vulnarable == vulnerability:
                        res = True
    return res


# def make_file():
def make_file(contractss, labelss):


    # لیست دو بعدی خود را تعریف کنید (به عنوان مثال)


    # # لیست دو بعدی خود را تعریف کنید (به عنوان مثال)
    # data = [
    #     ["آلیس", 30, "مهندس"],
    #     ["باب", 35, "برنامه‌نویس"],
    #     ["کارول", 25, "طراح"],
    # ]

    # لیست یک بعدی جدید را تعریف کنید که می‌خواهید به ستون آخر اضافه کنید
    # new_column_data = ["مقدار1", "مقدار2", "مقدار3"]
    print("----->", len(contractss[0]))
    # تعداد ستون‌ها را مشخص کنید
    num_columns = len(contractss[0])

    # ایجاد DataFrame از لیست دو بعدی
    df = pd.DataFrame(contractss)

    # افزودن ستون "ردیف" با شماره‌گذاری
    df.insert(0, "ردیف", range(1, len(df) + 1))

    # افزودن ستون جدید با داده‌های لیست جدید
    df[num_columns + 1] = labelss

    # نام فایل Excel را تعیین کنید
    excel_file = f"{ROOT}\script\\Integer_overflow.xlsx"
    print(excel_file)
    # ذخیره داده در فایل Excel
    df.to_excel(excel_file, index=False, header=False)

    print(f"فایل Excel '{excel_file}' با موفقیت ایجاد شد.")


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


def read_text_file(file_path, name):
    with open(file_path, encoding="utf8") as f:
        smartContractContent = f.read()
        isVulnarable = getResultVulnarable(name)

        words = run_task_04(smartContractContent)
        # words = run_tasks(smartContractContent)
        # words = run_task02(smartContractContent)
        # Example: Accessing word embeddings
        # print(words)
        # model = Word2Vec([words], vector_size=300, window=5, min_count=1, sg=0)
        # print("words", words)
        # model = gensim.models.Word2Vec(words, vector_size=300, window=5, min_count=1, sg=0)
        # w2v_model = Word2Vec(vector_size=300, window=5, min_count=1, sg=0)
        # w2v_model = Word2Vec(min_count=20,
        #                      window=2,
        #                      vector_size=300,
        #                      sample=6e-5,
        #                      alpha=0.03,
        #                      min_alpha=0.0007,
        #                      negative=20,
        #                      workers=4)
        #
        # modellll = w2v_model.build_vocab(words, progress_per=10000)

        # model = Word2Vec(words, vector_size=300, window=5, min_count=1, sg=1)
        # word_vectors = model.wv

        model = Word2Vec(words, min_count=1, vector_size=300, sg=0)  # sg=0: CBOW; sg=1: Skip-Gram
        sssss = model.wv
        frrf=vectorize(sssss,words)
        # eded= sssss.vectorize(words)


        print("len model", frrf)
        # Vectors
        # print(model.wv.vectors)

        contracts.append(sssss)
        # print("contracts", contracts)

        isVal = 0
        if (isVulnarable):
            isVal = 1

        labels.append(isVal)


os.chdir(path)


if __name__ == '__main__':
    print("MAKE EXCEL FILE")
    for sss in ["1"]:
        for file in os.listdir():
            # Check whether file is in text format or not
            if file.endswith(".sol"):
                file_path = f"{path}\{file}"
                name = file.replace(".sol","")
                read_text_file(file_path, name)
make_file(contracts, labels)
# make_file()
