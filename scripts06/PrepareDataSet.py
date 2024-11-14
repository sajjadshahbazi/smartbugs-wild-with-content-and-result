import json
import re
import os
import pandas as pd
from tensorflow.keras.preprocessing.sequence import pad_sequences
from gensim.models import Word2Vec
import numpy as np
import pickle
import PreProcessTools
import numpy as np
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

output_name = 'icse20'

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
CACHE_DIR = os.path.join(ROOT, 'cachefiles')
cache_path = os.path.join(CACHE_DIR, 'tokenized_fragments.pkl')
vulnerability_fd = open(os.path.join(ROOT, 'metadata', 'vulnerabilities.csv'), 'w', encoding='utf-8')

# PATH = f"{ROOT}\\contracts\\"  # main data set
PATH = f"{ROOT}\\contracts\\"  # part of main data set
# PATH = f"{ROOT}\\contra\\"  # one smart contract
os.chdir(PATH)

final_df = pd.DataFrame(columns=['X', 'Y'])

def is_sentence_in_text(sentence, text):
    sentence = sentence.lower()
    text = text.lower()
    text = re.sub(r'[^a-z ]', '', text)
    flg = sentence in text
    # print(flg)

    return flg


def refine_labels_for_reentrancy(df):
    for i, row in df[df['Vul'] == 1].iterrows():
        frag = row['Frag']

        # اگر خط خالی یا فقط شامل کامنت است، آن را ایمن فرض می‌کنیم
        if re.match(r'^\s*$', frag) or frag.strip().startswith('//'):
            df.at[i, 'Vul'] = 0  # خط خالی یا کامنت ایمن است

        # بررسی اینکه آیا فراخوانی خارجی واقعی و خطرناک است یا خیر
        elif re.search(r'\.call\(|\.send\(|\.transfer\(', frag):
            df.at[i, 'Vul'] = 1  # فراخوانی خارجی ممکن است همچنان آسیب‌پذیر باشد
        else:
            df.at[i, 'Vul'] = 0  # سایر خطوط در این محدوده ممکن است ایمن باشند



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


def main(file_path, name, target_vulnerability):
    global final_df
    with open(file_path, encoding="utf8") as f:
        smartContractContent = f.read()
        isVulnarable, vulnerable_lines = getResultVulnarable(name, target_vulnerability)

        # get fragments
        fragments = PreProcessTools.get_fragments(smartContractContent)

        vulnerability_status = [1 if (i+1) in vulnerable_lines else 0 for i in range(len(fragments))]

        data_fr = pd.DataFrame({
            'Vul': vulnerability_status,
            'Frag': fragments
        })
        data_fr = data_fr[~data_fr['Frag'].str.strip().isin(['', '}'])]
        refine_labels_for_reentrancy(data_fr)



        # **افزودن فرگمنت‌های خالی در صورت نیاز**
        fragment_count = len(data_fr)
        padding_needed = sequence_length - (fragment_count % sequence_length) if (fragment_count % sequence_length) != 0 else 0

        if padding_needed > 0:
            # اگر به padding نیاز بود، فرگمنت‌های خالی با لیبل ۰ اضافه می‌شوند
            empty_fragments = [''] * padding_needed
            empty_labels = [0] * padding_needed  # لیبل ۰ برای فرگمنت‌های خالی
            padding_df = pd.DataFrame({'Vul': empty_labels, 'Frag': empty_fragments})
            data_fr = pd.concat([data_fr, padding_df], ignore_index=True)

        dataframes_list.append(data_fr)

    combined_dataf = pd.concat(dataframes_list, ignore_index=True)
    combined_dataf = combined_dataf[~combined_dataf['Frag'].str.strip().isin(['', '}'])]

    X, Y = tokenize_fragments(combined_dataf)
    # print(f"-------------------------------->>>> {len(X)} , {len(Y)}")
    # print(f"-------------------------------->>>> {X}")
    # print(f"Length of X: {len(X)}, Shape of X: {X.shape}")
    # print(f"Length of Y: {len(Y)}, Shape of Y: {Y.shape}")
    contract_df = pd.DataFrame({'X': list(X), 'Y': Y})
    final_df = pd.concat([final_df, contract_df], ignore_index=True)




def get_word2vec_embeddings(text, word2vec_model):
    embeddings = [word2vec_model.wv[word] for word in text if word in word2vec_model.wv]
    return embeddings



def tokenize_fragments(combined_df):
    # لیست توکن‌های هر خط از کد
    tokenized_texts = [line.split() for line in combined_df['Frag']]

    # آموزش مدل Word2Vec
    word2vec_model = Word2Vec(sentences=tokenized_texts, vector_size=200, window=5, min_count=1, workers=4)

    # تبدیل خطوط کد به بردارهای word2vec با حفظ توالی‌ها
    X_padded = []
    for line in combined_df['Frag']:
        # تبدیل هر کلمه به بردار word2vec، یا بردار صفر اگر کلمه در مدل نباشد
        embeddings = [word2vec_model.wv[word] if word in word2vec_model.wv else np.zeros(200) for word in line.split()]

        # پد کردن هر خط به طول ثابت sequence_length
        if len(embeddings) < sequence_length:
            embeddings += [np.zeros(200)] * (sequence_length - len(embeddings))  # افزودن بردار صفر
        else:
            embeddings = embeddings[:sequence_length]  # برش به طول ثابت sequence_length

        X_padded.append(embeddings)

    # تبدیل به آرایه سه‌بعدی
    X = np.array(X_padded)
    # X = np.array(X_padded, dtype='float32')
    Y = combined_df['Vul'].values

    return X, Y


# def tokenize_fragments(combined_df):
#     # لیست توکن‌های هر خط از کد
#     tokenized_texts = [line.split() for line in combined_df['Frag']]
#
#     # آموزش مدل Word2Vec
#     word2vec_model = Word2Vec(sentences=tokenized_texts, vector_size=200, window=5, min_count=1, workers=4)
#
#     # تبدیل خطوط کد به بردارهای word2vec و محاسبه میانگین
#     X = [get_word2vec_embeddings(line.split(), word2vec_model) for line in combined_df['Frag']]
#     X = [np.array(seq).mean(axis=0) if len(seq) > 0 else np.zeros(word2vec_model.vector_size) for seq in X]
#
#     # پد کردن توالی‌ها به طول ثابت
#     X = pad_sequences([X], maxlen=200, dtype='float32', padding='post')
#     Y = combined_df['Vul'].values
#
#     return X, Y

# def tokenize_fragments(combined_df):
#     tokenized_texts = [line.split() for line in combined_df['Frag']]
#     word2vec_model = Word2Vec(sentences=tokenized_texts, vector_size=200, window=5, min_count=1, workers=4)
#
#     # استخراج بردارهای word2vec و محاسبه میانگین هر خط
#     X = [get_word2vec_embeddings(line.split(), word2vec_model) for line in combined_df['Frag']]
#     X = [np.array(seq).mean(axis=0) if len(seq) > 0 else np.zeros(word2vec_model.vector_size) for seq in X]
#
#     # تبدیل `X` به شکل سه‌بعدی و تقسیم به توالی‌های طول ثابت `sequence_length`
#     X = np.array(X)
#     X = X.reshape(-1, sequence_length, word2vec_model.vector_size)
#     Y = combined_df['Vul'].values
#     print("Shape of X in train_LSTM:", X.shape)
#
#     return X, Y

# def tokenize_fragments(combined_df):
#     tokenized_texts = [line.split() for line in combined_df['Frag']]
#     word2vec_model = Word2Vec(sentences=tokenized_texts, vector_size=200, window=5, min_count=1, workers=4)
#
#     # استخراج بردارهای word2vec و محاسبه میانگین هر خط
#     X = [get_word2vec_embeddings(line.split(), word2vec_model) for line in combined_df['Frag']]
#     X = [np.array(seq).mean(axis=0) if len(seq) > 0 else np.zeros(word2vec_model.vector_size) for seq in X]
#
#     # پد کردن هر بردار به صورت جداگانه
#     X = pad_sequences(X, maxlen=sequence_length, dtype='float32', padding='post')
#     Y = combined_df['Vul'].values
#
#     return X, Y

def train_LSTM():
    # فرض کنید X و Y را از final_df استخراج کرده‌اید
    X = np.array(final_df['X'].tolist())
    Y = np.array(final_df['Y'].tolist())


    print("Shape of X in train_LSTM:", X.shape)








    # تقسیم داده‌ها به آموزش و تست
    X_train, X_test, Y_train, Y_test = train_test_split(X, Y, test_size=0.2, random_state=42)

    # ساخت مدل LSTM
    model = Sequential()
    model.add(LSTM(128, input_shape=(sequence_length, X.shape[2]), return_sequences=True))
    model.add(Dropout(0.2))
    model.add(LSTM(64))
    model.add(Dropout(0.2))
    model.add(Dense(1, activation='sigmoid'))

    # کامپایل مدل
    model.compile(optimizer=Adam(learning_rate=0.001), loss='binary_crossentropy', metrics=['accuracy'])

    # آموزش مدل
    model.fit(X_train, Y_train, epochs=10, batch_size=32, validation_split=0.1)

    # پیش‌بینی روی داده‌های تست
    Y_pred = (model.predict(X_test) > 0.5).astype("int32")

    # محاسبه معیارها
    print("Accuracy:", accuracy_score(Y_test, Y_pred))
    print("Classification Report:")
    print(classification_report(Y_test, Y_pred, target_names=['Safe', 'Vulnerable']))

if __name__ == "__main__":
    final_df = load_dataframe_from_cache(cache_path)

    if final_df.empty:
        for file in os.listdir():
            # Check whether file is in text format or not
            if file.endswith(".sol"):
                file_path = f"{PATH}\{file}"
                name = file.replace(".sol", "")
                main(file_path, name, target_vulner)
                # if (main(file_path, name, target_vulner)):
                #     vul_count += 1
                # else:
                #     safe_count += 1

        save_dataframe_to_cache(final_df, cache_path)
        print(f"Calculated {final_df.count()}")

    else:
        print(f"Cached {final_df.count()}")



    train_LSTM()

