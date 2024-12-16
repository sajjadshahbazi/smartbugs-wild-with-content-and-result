import json
import re
import os
from pathlib import Path

import pandas as pd
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.models import Sequential
from tensorflow.keras.utils import Sequence
import sys
from gensim.models import Word2Vec
import numpy as np
import pickle
import PreProcessTools
import numpy as np
import sys
import io
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import LSTM, Dense, Dropout
from tensorflow.keras.optimizers import Adam



duration_stat = {}
count = {}
output = {}
safe_count = 0
vul_count = 0
labels = []
fragment_contracts = []
dataframes_list = []
batch_size = 1000  # کاهش اندازه دسته به 500 قرارداد
output_name = 'icse20'
vector_length = 100
vulnerability_stat = {
}
tool_stat = {}
tool_category_stat = {}
total_duration = 0
contract_vulnerabilities = {}
sequence_length = 10
vulnerability_mapping = {}

tools = ['mythril', 'slither', 'osiris', 'smartcheck', 'manticore', 'maian', 'securify',
         'honeybadger']  # all tools analizer

target_vulnerability_integer_overflow = 'Integer Overflow'  # sum safe smart contract: 28953, sum vulnarable smart contract: 18445
target_vulnerability_reentrancy = 'Reentrancy'  # sum safe smart contract: 38423, sum vulnarable smart contract: 8975
target_vulnerability_transaction_order_dependence = 'Transaction order dependence'  # sum safe smart contract: 45380, sum vulnarable smart contract: 2018
target_vulnerability_timestamp_dependency = 'timestamp'  # sum safe smart contract: 45322 , sum vulnarable smart contract: 2076
target_vulnerability_callstack_depth_attack = 'Depth Attack'  # sum safe smart contract: 45380 , sum vulnarable smart contract: 2018
target_vulnerability_integer_underflow = 'Integer Underflow'  # sum safe smart contract: 43727 , sum vulnarable smart contract: 3671

target_vulner = target_vulnerability_reentrancy

ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), '..'))
CACHE_DIR = os.path.join(ROOT, 'vectorcollections')
cache_path = os.path.join(CACHE_DIR, 'tokenized_fragments.pkl')
vulnerability_fd = open(os.path.join(ROOT, 'metadata', 'vulnerabilities.csv'), 'w', encoding='utf-8')

# PATH = f"{ROOT}\\contracts\\"  # main data set
PATH = f"{ROOT}\\contract\\"  # part of main data set
# PATH = f"{ROOT}\\contra\\"  # one smart contract

# PATH = os.path.join(ROOT, 'contract') # linux
os.chdir(PATH)

final_df = pd.DataFrame(columns=['X', 'Y'])




def is_sentence_in_text(sentence, text):
    sentence = sentence.lower()
    text = text.lower()
    text = re.sub(r'[^a-z ]', '', text)
    flg = sentence in text
    # print(flg)

    return flg



def load_dataframe_from_cache(cache_path):
    if os.path.exists(cache_path):
        with open(cache_path, 'rb') as f:
            return pickle.load(f)
    return pd.DataFrame(columns=['X', 'Y'])

def save_dataframe_to_cache(df, cache_path):
    with open(cache_path, 'wb') as f:
        pickle.dump(df, f)

def getResultVulnarable(contract_name, target_vulnerability):

    total_duration = 0
    res = False
    lines = []
    for tool in tools:
        path_result = os.path.join(f"{ROOT}\\results\\", tool, output_name, contract_name, 'result.json')
        # path_result = os.path.join(f"{ROOT}results", tool, output_name, contract_name, 'result.json') Linux
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
                            lines.extend([result['lineno']])

            elif tool == 'oyente' or tool == 'osiris' or tool == 'honeybadger':
                for analysis in data['analysis']:
                    if analysis['errors'] is not None:
                        for result in analysis['errors']:
                            vulnerability = result['message'].strip()
                            if is_sentence_in_text(target_vulnerability, vulnerability):
                                res = True
                                lines.extend([result['line']])

            elif tool == 'manticore':
                for analysis in data['analysis']:
                    for result in analysis:
                        vulnerability = result['name'].strip()
                        if is_sentence_in_text(target_vulnerability, vulnerability):
                            res = True
                            lines.extend([result['line']])

            elif tool == 'maian':
                for vulnerability in data['analysis']:
                    if data['analysis'][vulnerability]:
                        if is_sentence_in_text(target_vulnerability, vulnerability):
                            res = True
                            # None lines

            elif tool == 'securify':
                for f in data['analysis']:
                    analysis = data['analysis'][f]['results']
                    for vulnerability in analysis:
                        for line in analysis[vulnerability]['violations']:
                            if is_sentence_in_text(target_vulnerability, vulnerability):
                                print("!!!!!! Find Vulnarability - securify !!!!!")
                                res = True
                                lines.extend([line + 1])

            elif tool == 'slither':
                analysis = data['analysis']
                for result in analysis:
                    vulnerability = result['check'].strip()
                    line = None
                    if 'source_mapping' in result['elements'][0] and len(
                            result['elements'][0]['source_mapping']['lines']) > 0:
                        line = result['elements'][0]['source_mapping']['lines']
                    if is_sentence_in_text(target_vulnerability, vulnerability):
                        if line is not None:
                            res = True
                            lines.extend(line)

            elif tool == 'smartcheck':
                analysis = data['analysis']
                for result in analysis:
                    vulnerability = result['name'].strip()
                    if is_sentence_in_text(target_vulnerability, vulnerability):
                        res = True
                        lines.extend([result['line']])

            elif tool == 'solhint':
                analysis = data['analysis']
                for result in analysis:
                    vulnerability = result['type'].strip()
                    if is_sentence_in_text(target_vulnerability, vulnerability):
                        res = True
                        lines.extend([int(result['line'])])

    return res, lines


def load_batches():
    os.makedirs(CACHE_DIR, exist_ok=True)
    X_batches, Y_batches = [], []
    for file in os.listdir(CACHE_DIR):
        with open(os.path.join(CACHE_DIR, file), 'rb') as f:
            X, Y = pickle.load(f)
            X_batches.append(X)
            Y_batches.append(Y)
    return np.vstack(X_batches), np.hstack(Y_batches)

# تابع پردازش دسته‌ها و ذخیره در فایل‌های pickle
def process_batch(files, target_vulnerability):
    dataframes_list = []
    for file in files:
        with open(file, encoding="utf8") as f:
            smartContractContent = f.read()
            fragments = PreProcessTools.get_fragments(smartContractContent)

            name = Path(file).stem

            res, vulnerable_lines = getResultVulnarable(name, target_vulnerability)

            if not res:
                print(f"No vulnerability found in contract: {name}. Skipping...")
                continue  # به قرارداد بعدی بروید

            vulnerability_status = [1 if (i + 1) in vulnerable_lines else 0 for i in range(len(fragments))]

            data_fr = pd.DataFrame({'Vul': vulnerability_status, 'Frag': fragments})
            data_fr = data_fr[~data_fr['Frag'].str.strip().isin(['', '}'])]
            padding_needed = sequence_length - (len(data_fr) % sequence_length) if (len(data_fr) % sequence_length) != 0 else 0
            if padding_needed > 0:
                empty_fragments = [''] * padding_needed
                empty_labels = [0] * padding_needed
                padding_df = pd.DataFrame({'Vul': empty_labels, 'Frag': empty_fragments})
                data_fr = pd.concat([data_fr, padding_df], ignore_index=True)

            dataframes_list.append(data_fr)

    combined_dataf = pd.concat(dataframes_list, ignore_index=True)
    X, Y = tokenize_fragments(combined_dataf)

    batch_file = os.path.join(CACHE_DIR, f"batch_{len(os.listdir(CACHE_DIR))}.pkl")
    with open(batch_file, 'wb') as f:
        pickle.dump((X, Y), f)
    print(f"Batch saved to {batch_file}")

# تابع تبدیل داده‌ها به بردارهای Word2Vec
def tokenize_fragments(combined_df):
    tokenized_texts = [line.split() for line in combined_df['Frag']]
    word2vec_model = Word2Vec(sentences=tokenized_texts, vector_size=vector_length, window=5, min_count=1, workers=4)
    X_padded = []
    for line in combined_df['Frag']:
        embeddings = [word2vec_model.wv[word] if word in word2vec_model.wv else np.zeros(vector_length) for word in line.split()]
        embeddings = embeddings[:sequence_length] + [np.zeros(vector_length)] * (sequence_length - len(embeddings))
        X_padded.append(embeddings)
    X = np.array(X_padded, dtype='float32')  # استفاده از float16 برای کاهش مصرف حافظه
    Y = combined_df['Vul'].values
    return X, Y


def train_LSTM():
    # بارگذاری کل داده‌ها از CACHE_DIR
    X, Y = load_batches()  # تمام داده‌ها از فایل‌های پردازش‌شده بارگذاری می‌شود

    # بررسی ابعاد داده‌ها
    print(f"Shape of X: {X.shape}")
    print(f"Shape of Y: {Y.shape}")
    print("Distribution in Y:", np.unique(Y, return_counts=True))

    unique, counts = np.unique(Y, return_counts=True)
    label_distribution = dict(zip(unique, counts))
    print("Label Distribution:", label_distribution)

    # نسبت لیبل‌ها
    total_samples = len(Y)
    for label, count in label_distribution.items():
        print(f"Label {label}: {count} samples ({(count / total_samples) * 100:.2f}%)")


    # تقسیم داده‌ها به آموزش و تست
    X_train, X_test, Y_train, Y_test = train_test_split(X, Y, test_size=0.2, random_state=42)
    print("Distribution in Y_test:", np.unique(Y_test, return_counts=True))

    # تعریف مدل LSTM
    model = Sequential([
        LSTM(128, input_shape=(sequence_length, vector_length), return_sequences=True),
        Dropout(0.2),
        LSTM(32),
        Dropout(0.2),
        Dense(1, activation='sigmoid')
    ])

    # کامپایل مدل
    model.compile(optimizer=Adam(learning_rate=0.001), loss='binary_crossentropy', metrics=['accuracy'])

    # آموزش مدل با داده‌های کامل
    # class_weights = {0: 1., 1: 20}  # این اعداد به طور مثال هستند و باید آن‌ها را براساس توزیع داده‌ها تنظیم کنید
    # model.fit(X_train, Y_train, epochs=10, batch_size=32, validation_split=0.1, class_weight=class_weights)
    model.fit(X_train, Y_train, epochs=10, batch_size=32, validation_split=0.1, verbose=2)

    # پیش‌بینی روی داده‌های تست
    Y_pred = (model.predict(X_test) > 0.5).astype("int32")

    # محاسبه معیارها
    accuracy = accuracy_score(Y_test, Y_pred)
    report = classification_report(Y_test, Y_pred, target_names=['Safe', 'Vulnerable'], labels=[0, 1])


    print(f"Accuracy: {accuracy}")
    print("Classification Report:")
    print(report)

    # ذخیره مدل
    model.save('final_model.h5')
    print("Training complete.")


if __name__ == "__main__":

    files = [os.path.join(PATH, f) for f in os.listdir(PATH) if f.endswith(".sol")]
    for i in range(0, len(files), batch_size):
        batch_files = files[i:i + batch_size]
        process_batch(batch_files, target_vulner)

    train_LSTM()

