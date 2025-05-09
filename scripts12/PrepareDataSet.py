import json
import re
import os
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




sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')



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
# PATH = f"{ROOT}\\contracts\\"  # part of main data set
# PATH = f"{ROOT}\\contra\\"  # one smart contract

PATH = os.path.join(ROOT, 'contracts') # linux
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
        path_result = os.path.join(f"{ROOT}results", tool, output_name, contract_name, 'result.json')
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


def load_batches():
    os.makedirs(CACHE_DIR, exist_ok=True)
    X_batches, Y_batches = [], []
    for file in os.listdir(CACHE_DIR):
        with open(os.path.join(CACHE_DIR, file), 'rb') as f:
            X, Y = pickle.load(f)
            X_batches.append(X)
            Y_batches.append(Y)
    return np.vstack(X_batches), np.hstack(Y_batches)

# def main(file_path, name, target_vulnerability):
#     global final_df
#     with open(file_path, encoding="utf8") as f:
#         smartContractContent = f.read()
#         isVulnarable, vulnerable_lines = getResultVulnarable(name, target_vulnerability)
#
#         # get fragments
#         fragments = PreProcessTools.get_fragments(smartContractContent)
#
#         vulnerability_status = [1 if (i+1) in vulnerable_lines else 0 for i in range(len(fragments))]
#
#         data_fr = pd.DataFrame({
#             'Vul': vulnerability_status,
#             'Frag': fragments
#         })
#         data_fr = data_fr[~data_fr['Frag'].str.strip().isin(['', '}'])]
#         refine_labels_for_reentrancy(data_fr)
#
#
#
#         # **افزودن فرگمنت‌های خالی در صورت نیاز**
#         fragment_count = len(data_fr)
#         padding_needed = sequence_length - (fragment_count % sequence_length) if (fragment_count % sequence_length) != 0 else 0
#
#         if padding_needed > 0:
#             # اگر به padding نیاز بود، فرگمنت‌های خالی با لیبل ۰ اضافه می‌شوند
#             empty_fragments = [''] * padding_needed
#             empty_labels = [0] * padding_needed  # لیبل ۰ برای فرگمنت‌های خالی
#             padding_df = pd.DataFrame({'Vul': empty_labels, 'Frag': empty_fragments})
#             data_fr = pd.concat([data_fr, padding_df], ignore_index=True)
#
#         dataframes_list.append(data_fr)
#
#     combined_dataf = pd.concat(dataframes_list, ignore_index=True)
#     combined_dataf = combined_dataf[~combined_dataf['Frag'].str.strip().isin(['', '}'])]
#
#     X, Y = tokenize_fragments(combined_dataf)
#     # print(f"-------------------------------->>>> {len(X)} , {len(Y)}")
#     # print(f"-------------------------------->>>> {X}")
#     # print(f"Length of X: {len(X)}, Shape of X: {X.shape}")
#     # print(f"Length of Y: {len(Y)}, Shape of Y: {Y.shape}")
#     contract_df = pd.DataFrame({'X': list(X), 'Y': Y})
#     final_df = pd.concat([final_df, contract_df], ignore_index=True)




# def get_word2vec_embeddings(text, word2vec_model):
#     embeddings = [word2vec_model.wv[word] for word in text if word in word2vec_model.wv]
#     return embeddings



# def tokenize_fragments(combined_df):
#     tokenized_texts = [line.split() for line in combined_df['Frag']]
#     word2vec_model = Word2Vec(sentences=tokenized_texts, vector_size=vector_length, window=5, min_count=1, workers=4)
#     X_padded = []
#     for line in combined_df['Frag']:
#         embeddings = [word2vec_model.wv[word] if word in word2vec_model.wv else np.zeros(vector_length) for word in line.split()]
#         embeddings = embeddings[:sequence_length] + [np.zeros(vector_length)] * (sequence_length - len(embeddings))
#         X_padded.append(embeddings)
#     X = np.array(X_padded, dtype='float16')
#     Y = combined_df['Vul'].values
#     return X, Y

# def process_batch(files, target_vulnerability):
#     dataframes_list = []
#     for file in files:
#         with open(file, encoding="utf8") as f:
#             smartContractContent = f.read()
#             vulnerable_lines = getResultVulnarable(file, target_vulnerability)
#             fragments = PreProcessTools.get_fragments(smartContractContent)
#             vulnerability_status = [1 if (i + 1) in vulnerable_lines else 0 for i in range(len(fragments))]
#
#             data_fr = pd.DataFrame({'Vul': vulnerability_status, 'Frag': fragments})
#             data_fr = data_fr[~data_fr['Frag'].str.strip().isin(['', '}'])]
#
#             # پد کردن برای طول ثابت sequence_length
#             padding_needed = sequence_length - (len(data_fr) % sequence_length) if (len(data_fr) % sequence_length) != 0 else 0
#             if padding_needed > 0:
#                 empty_fragments = [''] * padding_needed
#                 empty_labels = [0] * padding_needed
#                 padding_df = pd.DataFrame({'Vul': empty_labels, 'Frag': empty_fragments})
#                 data_fr = pd.concat([data_fr, padding_df], ignore_index=True)
#
#             dataframes_list.append(data_fr)
#
#     combined_dataf = pd.concat(dataframes_list, ignore_index=True)
#     X, Y = tokenize_fragments(combined_dataf)
#
#     # ذخیره داده‌های پردازش شده به صورت دسته‌ای
#     batch_file = os.path.join(CACHE_DIR, f"batch_{len(os.listdir(CACHE_DIR))}.pkl")
#     with open(batch_file, 'wb') as f:
#         pickle.dump((X, Y), f)
#     print(f"Batch saved to {batch_file}")

# def load_batches():
#     X_batches, Y_batches = [], []
#     for file in os.listdir(CACHE_DIR):
#         with open(os.path.join(CACHE_DIR, file), 'rb') as f:
#             X, Y = pickle.load(f)
#             X_batches.append(X)
#             Y_batches.append(Y)
#     return np.vstack(X_batches), np.hstack(Y_batches)

# def train_LSTM():
#     X, Y = load_batches()
#     X_train, X_test, Y_train, Y_test = train_test_split(X, Y, test_size=0.2, random_state=42)
#     model = Sequential([
#         LSTM(128, input_shape=(sequence_length, X.shape[2]), return_sequences=True),
#         Dropout(0.2),
#         LSTM(64),
#         Dropout(0.2),
#         Dense(1, activation='sigmoid')
#     ])
#     model.compile(optimizer=Adam(learning_rate=0.001), loss='binary_crossentropy', metrics=['accuracy'])
#     model.fit(X_train, Y_train, epochs=10, batch_size=32, validation_split=0.1)
#     Y_pred = (model.predict(X_test) > 0.5).astype("int32")
#     print("Accuracy:", accuracy_score(Y_test, Y_pred))
#     print("Classification Report:")
#     print(classification_report(Y_test, Y_pred, target_names=['Safe', 'Vulnerable']))

class DataGenerator(Sequence):
    def __init__(self, cache_dir, batch_size):
        self.cache_dir = cache_dir
        self.batch_size = batch_size
        self.files = os.listdir(cache_dir)
        self.num_files = len(self.files)  # تعداد کل فایل‌ها

    def __len__(self):
        return self.num_files

    def __getitem__(self, index):
        # تنظیم اندیس برای چرخش در بین فایل‌ها
        index = index % self.num_files
        file_path = os.path.join(self.cache_dir, self.files[index])
        with open(file_path, 'rb') as f:
            X, Y = pickle.load(f)
        return X, Y

    def on_epoch_end(self):
        # بازآرایی فایل‌ها برای جلوگیری از مشکلات مربوط به ترتیب
        np.random.shuffle(self.files)


# تابع پردازش دسته‌ها و ذخیره در فایل‌های pickle
def process_batch(files, target_vulnerability):
    dataframes_list = []
    for file in files:
        with open(file, encoding="utf8") as f:
            smartContractContent = f.read()
            fragments = PreProcessTools.get_fragments(smartContractContent)
            res, vulnerable_lines = getResultVulnarable(file, target_vulnerability)
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

# تابع آموزش مدل با داده‌های مرحله‌ای
def train_LSTM():
    generator = DataGenerator(CACHE_DIR, batch_size)

    model = Sequential([
        LSTM(128, input_shape=(sequence_length, vector_length), return_sequences=True),
        Dropout(0.2),
        LSTM(32),
        Dropout(0.2),
        Dense(1, activation='sigmoid')
    ])
    model.compile(optimizer=Adam(learning_rate=0.001), loss='binary_crossentropy', metrics=['accuracy'])

    # تنظیم مقدار steps_per_epoch
    steps_per_epoch = len(generator) * 10

    # آموزش مدل
    model.fit(generator, epochs=10, steps_per_epoch=steps_per_epoch, verbose=2)

    # پیش‌بینی با استفاده از مدل
    X_test, Y_test = load_batches()  # داده‌های تست باید از قبل جدا شوند
    Y_pred = (model.predict(X_test) > 0.5).astype("int32")  # پیش‌بینی کلاس‌ها (0 یا 1)

    # محاسبه معیارها
    accuracy = accuracy_score(Y_test, Y_pred)
    report = classification_report(Y_test, Y_pred, target_names=['Safe', 'Vulnerable'])

    print(f"Accuracy: {accuracy}")
    print("Classification Report:")
    print(report)

    model.save('final_model.h5')
    print("Training complete.")


if __name__ == "__main__":
    # ساخت مسیر پویا
    # log_path = os.path.join(ROOT, "logs", "output_log.txt")
    #
    # # اطمینان از وجود پوشه
    # os.makedirs(os.path.dirname(log_path), exist_ok=True)
    #
    # # باز کردن فایل
    # log_file = open(log_path, "w")
    # sys.stdout = log_file  # هدایت خروجی به فایل
    #
    # print("This message will be saved in the log file.")



    print("!!!!!!!!!!!!!!!!!!!!!!!!!")

    files = [os.path.join(PATH, f) for f in os.listdir(PATH) if f.endswith(".sol")]
    for i in range(0, len(files), batch_size):
        batch_files = files[i:i + batch_size]
        process_batch(batch_files, target_vulner)

    train_LSTM()


    # sys.stdout = sys.__stdout__  # بازگرداندن خروجی به حالت اولیه
    # log_file.close()
