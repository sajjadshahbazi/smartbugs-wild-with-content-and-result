import json
import re
import os
from pathlib import Path
from imblearn.over_sampling import SMOTE
import pandas as pd
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.utils import Sequence
import sys
from gensim.models import Word2Vec
import numpy as np
import pickle
import PreProcessTools
import numpy as np
import io
from tensorflow.keras import backend as K
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
from tensorflow.keras.models import Sequential
# from tensorflow.keras.layers import Conv1D, Bidirectional, LSTM, Dropout, Dense
from tensorflow.keras.layers import Embedding, Bidirectional, GRU, Dropout, Dense
from tensorflow.keras.callbacks import EarlyStopping
from tensorflow.keras.optimizers import Adam
import tensorflow as tf
from tensorflow.python.platform import build_info as tf_build_info

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
vector_length = 300
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

PATH = f"{ROOT}\\contracts\\"  # main data set
# PATH = f"{ROOT}\\contract\\"  # part of main data set
# PATH = f"{ROOT}\\contra\\"  # one smart contract

# PATH = os.path.join(ROOT, 'contract') # linux
os.chdir(PATH)

final_df = pd.DataFrame(columns=['X', 'Y'])


def focal_loss(alpha=0.25, gamma=2.0):
    """
    تابع Focal Loss برای مقابله با عدم توازن داده‌ها.
    :param alpha: وزن کلاس‌های نامتوازن
    :param gamma: تمرکز بر روی نمونه‌های سخت
    :return: تابع loss
    """
    def loss(y_true, y_pred):
        epsilon = K.epsilon()  # جلوگیری از log(0)
        y_pred = K.clip(y_pred, epsilon, 1. - epsilon)
        pt = y_true * y_pred + (1 - y_true) * (1 - y_pred)  # احتمال پیش‌بینی صحیح
        return -K.mean(alpha * K.pow(1. - pt, gamma) * K.log(pt))  # فرمول Focal Loss

    return loss


def is_sentence_in_text(sentence, text):
    sentence = sentence.lower()
    text = text.lower()
    text = re.sub(r'[^a-z ]', '', text)
    flg = sentence in text
    return flg



def load_batches(folder, file_extension=".pkl"):
    X_batches, Y_batches = [], []
    for file in os.listdir(folder):
        if file.endswith(file_extension):
            with open(os.path.join(folder, file), 'rb') as f:
                X, Y = pickle.load(f)
                X_batches.append(X)
                Y_batches.append(Y)
    return np.vstack(X_batches), np.hstack(Y_batches)


# def load_batches():
#     X_batches, Y_batches = [], []
#     for file in os.listdir(CACHE_DIR):
#         with open(os.path.join(CACHE_DIR, file), 'rb') as f:
#             X, Y = pickle.load(f)
#             X_batches.append(X)
#             Y_batches.append(Y)
#     return np.vstack(X_batches), np.hstack(Y_batches)
#
#
# def load_batches():
#     os.makedirs(CACHE_DIR, exist_ok=True)
#     X_batches, Y_batches = [], []
#     for file in os.listdir(CACHE_DIR):
#         with open(os.path.join(CACHE_DIR, file), 'rb') as f:
#             X, Y = pickle.load(f)
#             X_batches.append(X)
#             Y_batches.append(Y)
#     return np.vstack(X_batches), np.hstack(Y_batches)


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



SENSITIVE_OPERATORS_REETRANCY = ['call', 'delegatecall', 'send', 'transfer', 'selfdestruct']

def contains_sensitive_operator(function_body):
    """
    بررسی می‌کند که آیا فانکشن شامل عملگرهای حساس است یا خیر.
    """
    for operator in SENSITIVE_OPERATORS_REETRANCY:
        if operator in function_body:
            return True
    return False


def save_to_file(data, file_prefix, cache_dir, batch_size, batch_index):
    os.makedirs(cache_dir, exist_ok=True)  # اطمینان از وجود پوشه CACHE_DIR

    # ذخیره داده‌ها به صورت فایل‌های جداگانه در CACHE_DIR
    for i in range(0, len(data), batch_size):
        batch = data[i:i + batch_size]
        filename = f"{file_prefix}_batch_{batch_index}_{i // batch_size}.pkl"  # نام‌گذاری دسته‌بندی‌شده
        filepath = os.path.join(cache_dir, filename)
        with open(filepath, 'wb') as f:
            pickle.dump(batch, f)
        print(f"Saved batch to {filepath}")



# def save_to_file(data, file_prefix, cache_dir, batch_size):
#     """
#     ذخیره فایل‌های دسته‌بندی شده در یک مسیر (CACHE_DIR) با نام‌گذاری مناسب.
#     :param data: داده‌هایی که باید ذخیره شوند (لیستی از نمونه‌ها).
#     :param file_prefix: پیشوند فایل (مثلاً 'vulnerable', 'sensitive_negative').
#     :param cache_dir: مسیر پوشه اصلی ذخیره (CACHE_DIR).
#     :param batch_size: تعداد نمونه‌ها در هر فایل.
#     """
#     os.makedirs(cache_dir, exist_ok=True)  # اطمینان از وجود پوشه CACHE_DIR
#
#     # ذخیره داده‌ها به صورت فایل‌های جداگانه در CACHE_DIR
#     for i in range(0, len(data), batch_size):
#         batch = data[i:i + batch_size]
#         filename = f"{cache_dir}/{file_prefix}_batch_{i // batch_size}.pkl"  # نام‌گذاری دسته‌بندی‌شده
#         with open(filename, 'wb') as f:
#             pickle.dump(batch, f)
#         print(f"Saved batch to {filename}")


def extract_functions(code):
    """
    استخراج فانکشن‌ها از کد Solidity.
    این تابع فانکشن‌هایی که با 'function' شروع می‌شوند را شناسایی کرده
    و آنها را به صورت یک لیست برمی‌گرداند.

    :param code: کد کامل قرارداد به عنوان یک رشته (string).
    :return: لیستی از فانکشن‌ها که هرکدام به صورت یک رشته هستند.
    """
    functions = []

    # الگوی regex برای شناسایی فانکشن‌ها
    function_pattern = re.compile(
        r'function\s+\w+\s*\(.*\)\s*(public|private|internal|external)*\s*(view|pure)*\s*(returns\s*\(.*\))?\s*{')

    # جستجو برای تمام فانکشن‌ها
    matches = function_pattern.finditer(code)

    # پیدا کردن ابتدای هر فانکشن و استخراج آن
    for match in matches:
        function_start = match.start()
        function_end = code.find('}', function_start) + 1

        if function_end != -1:
            functions.append(code[function_start:function_end])

    return functions



# تابعی برای توکن‌سازی کد Solidity
def tokenize_solidity_code(code):
    # الگوی اصلاح‌شده برای شناسایی علائم خاص از جمله '}'
    pattern = r'\b(?:function|returns|uint256|internal|constant|assert|return|require|if|else|for|while)\b|[=<>!*&|()+\-;/\}]|\b[a-zA-Z_][a-zA-Z0-9_]*\b'

    # یافتن تمام توکن‌ها با استفاده از الگو
    tokens = re.findall(pattern, code)

    return tokens

def normalize_variables(tokens):
    normalized_tokens = []
    for token in tokens:
        # اگر توکن یک متغیر باشد (که معمولاً با نام‌های متغیرهای غیرکلیدی شروع می‌شود)، آن را نرمال می‌کنیم
        if re.match(r'[a-zA-Z_][a-zA-Z0-9_]*', token) and token not in ['function', 'returns', 'internal', 'constant', 'assert', 'return']:
            normalized_tokens.append('VAR')  # به جای اسم متغیر، 'VAR' قرار می‌دهیم
        elif token in ['}', '{', '(', ')', '[', ']', '.', ';', ',', '+', '-', '=', '!', '?', ':']:
            # لیست نمادهای خاص که باید حفظ شوند
            normalized_tokens.append(token)
        elif token.strip() == '':  # برای جلوگیری از ذخیره کردن فضاهای خالی
            continue  # هیچ کاری انجام ندهید اگر توکن خالی است
        else:
            normalized_tokens.append(token)
    return normalized_tokens

def extract_functions_with_bodies(contract_code):
    """
    استخراج فانکشن‌ها از کد Solidity به همراه بدنه و شماره خط شروع و پایان.
    :param contract_code: متن قرارداد به عنوان یک رشته
    :return: لیستی از دیکشنری‌ها شامل فانکشن، بدنه، خط شروع و پایان
    """
    functions = []

    # الگوی regex برای شناسایی تعریف فانکشن‌ها
    function_pattern = re.compile(
        r'function\s+\w+\s*\(.*?\)\s*(public|private|internal|external)?\s*(view|pure)?\s*(returns\s*\(.*?\))?\s*{')

    lines = contract_code.splitlines()  # تقسیم کد به خطوط
    open_brackets = 0
    in_function = False
    function_body = []
    start_line = 0

    for i, line in enumerate(lines):
        # اگر در فانکشن نیستیم به دنبال شروع فانکشن بگرد
        if not in_function:
            match = function_pattern.search(line)
            if match:
                in_function = True
                start_line = i + 1  # ثبت شماره خط شروع
                function_body = [line]
                open_brackets = line.count('{') - line.count('}')
        else:
            function_body.append(line)
            open_brackets += line.count('{')
            open_brackets -= line.count('}')

            # اگر تمام براکت‌ها بسته شد، فانکشن پایان یافته است
            if open_brackets == 0:
                end_line = i + 1  # ثبت شماره خط پایان
                functions.append({
                    'function_body': '\n'.join(function_body),
                    'start_line': start_line,
                    'end_line': end_line,
                    'label': 0
                })
                in_function = False

    return functions

def vectorize_tokens(tokens):
    """
    تبدیل یک لیست از توکن‌ها به آرایه‌ای از بردارهای ویژگی.

    :param tokens: لیست تک‌بعدی از توکن‌ها
    :return: آرایه دو‌بعدی (تعداد توکن‌ها × اندازه بردار)
    """
    # ایجاد مدل Word2Vec
    word2vec_model = Word2Vec(sentences=[tokens], vector_size=vector_length, window=5, min_count=1, workers=4)

    # تبدیل توکن‌ها به بردارهای Word2Vec
    embeddings = [
        word2vec_model.wv[word] if word in word2vec_model.wv else np.zeros(vector_length)
        for word in tokens
    ]

    # اعمال پدینگ در صورت نیاز
    embeddings = embeddings[:sequence_length] + [np.zeros(vector_length)] * max(0, sequence_length - len(embeddings))

    # تبدیل به آرایه NumPy
    return np.array(embeddings, dtype='float32')


def label_functions_by_vulnerable_lines(functions, vulnerable_lines):
    for func in functions:
        if any(func['start_line'] <= line <= func['end_line'] for line in vulnerable_lines):
            func['label'] = 1  # اگر خط آسیب‌پذیر در فانکشن باشد، لیبل ۱ می‌شود


# def process_batch_with_categorization(files, target_vulnerability, batch_size, batch_index):
#     X = []  # لیست برای ذخیره بردارها
#     Y = []  # لیست برای ذخیره برچسب‌ها
#     max_function_length = 50
#
#     sc_files = [f for f in files if f.endswith(".sol")]
#     print(f"cont {sc_files.__len__()}")
#     for file in sc_files:
#         with open(file, encoding="utf8") as f:
#             contract_content = f.read()
#
#             # استخراج فانکشن‌ها و خطوط آسیب‌پذیر
#             functions = extract_functions_with_bodies(contract_content)
#             name = Path(file).stem
#             res, vulnerable_lines = getResultVulnarable(name, target_vulnerability)
#
#             # لیبل‌گذاری
#             label_functions_by_vulnerable_lines(functions, vulnerable_lines)
#             for func in functions:
#                 fragments = PreProcessTools.get_fragments(func['function_body'])
#                 label = func['label']
#                 func_vectors = []
#
#                 for fragment in fragments:
#                     if fragment.strip():
#                         tokens = tokenize_solidity_code(fragment)
#                         if tokens:
#                             vectors = vectorize_tokens(tokens)
#                             func_vectors.extend(vectors)
#                 if func_vectors:
#                     padded_function = \
#                     pad_sequences([func_vectors], maxlen=max_function_length, padding='post', dtype='float32')[0]
#
#                     # افزودن به لیست‌های X و Y
#                     X.append(padded_function)
#                     Y.append(label)
#
#     # تبدیل لیست‌ها به آرایه‌های NumPy
#     X = np.array(X, dtype='float32')
#     Y = np.array(Y, dtype='int32')
#
#     # ذخیره داده‌ها
#     batch_file = os.path.join(CACHE_DIR, f"batch_{len(os.listdir(CACHE_DIR))}.pkl")
#     with open(batch_file, 'wb') as f:
#         pickle.dump((X, Y), f)
#     print(f"Batch saved to {batch_file}")


# def process_batch_with_categorization(files, target_vulnerability, batch_size, batch_index):
#     X = []  # لیست برای ذخیره بردارها
#     Y = []  # لیست برای ذخیره برچسب‌ها
#     max_function_length = 50
#
#     sc_files = [f for f in files if f.endswith(".sol")]
#     print(f"Number of .sol files: {len(sc_files)}")
#
#     for file in sc_files:
#         with open(file, encoding="utf8") as f:
#             contract_content = f.read()
#
#             # استخراج فانکشن‌ها و خطوط آسیب‌پذیر
#             functions = extract_functions_with_bodies(contract_content)
#             name = Path(file).stem
#             res, vulnerable_lines = getResultVulnarable(name, target_vulnerability)
#
#             # لیبل‌گذاری
#             label_functions_by_vulnerable_lines(functions, vulnerable_lines)
#             for func in functions:
#                 fragments = PreProcessTools.get_fragments(func['function_body'])
#                 label = func['label']
#                 func_vectors = []
#
#                 for fragment in fragments:
#                     if fragment.strip():
#                         tokens = tokenize_solidity_code(fragment)
#                         if tokens:
#                             vectors = vectorize_tokens(tokens)
#                             func_vectors.extend(vectors)
#
#                 if func_vectors:
#                     padded_function = pad_sequences(
#                         [func_vectors], maxlen=max_function_length, padding='post', dtype='float32'
#                     )[0]
#
#                     # اضافه کردن به X و Y
#                     if label == 1:
#                         # اگر آسیب‌پذیر باشد
#                         X.append(padded_function)
#                         Y.append(1)
#                     else:
#                         # اگر ایمن باشد
#                         if contains_sensitive_operator(func['function_body']):
#                             X.append(padded_function)
#                             Y.append(0)
#                         else:
#                             X.append(padded_function)
#                             Y.append(0)
#
#     # تبدیل لیست‌ها به آرایه‌های NumPy
#     X = np.array(X, dtype='float32')
#     Y = np.array(Y, dtype='int32')
#
#     # ذخیره داده‌ها
#     batch_file = os.path.join(CACHE_DIR, f"batch_{len(os.listdir(CACHE_DIR))}.pkl")
#     with open(batch_file, 'wb') as f:
#         pickle.dump((X, Y), f)
#     print(f"Batch saved to {batch_file}")


def process_batch_with_categorization(files, target_vulnerability, batch_size, batch_index):
    X_sensitive_negative, Y_sensitive_negative = [], []
    X_vulnerable, Y_vulnerable = [], []
    X_safe, Y_safe = [], []
    max_function_length = 50

    sc_files = [f for f in files if f.endswith(".sol")]
    print(f"cont {sc_files.__len__()}")
    for file in sc_files:
        with (open(file, encoding="utf8") as f):
            contract_content = f.read()

            # استخراج فانکشن‌ها و خطوط آسیب‌پذیر
            functions = extract_functions_with_bodies(contract_content)
            name = Path(file).stem
            res, vulnerable_lines = getResultVulnarable(name, target_vulnerability)

            # لیبل‌گذاری
            label_functions_by_vulnerable_lines(functions, vulnerable_lines)
            for func in functions:
                fragments = PreProcessTools.get_fragments(func['function_body'])
                label = func['label']
                func_vectors = []

                for fragment in fragments:
                    if fragment.strip():
                        tokens = tokenize_solidity_code(fragment)
                        if tokens:
                            vectors = vectorize_tokens(tokens)
                            func_vectors.extend(vectors)
                if func_vectors:
                    padded_function = pad_sequences([func_vectors], maxlen=max_function_length, padding='post', dtype='float32')[0]
                    # دسته‌بندی توابع

                    if label == 1:
                        X_vulnerable.append(padded_function)
                        Y_vulnerable.append(label)
                    else:
                        if contains_sensitive_operator(func['function_body']):
                            X_sensitive_negative.append(padded_function)
                            Y_sensitive_negative.append(label)
                        else:
                            X_safe.append(padded_function)
                            Y_safe.append(label)

    X_vulnerable = np.array(X_vulnerable, dtype='float32')
    Y_vulnerable = np.array(Y_vulnerable, dtype='int32')

    X_sensitive_negative = np.array(X_sensitive_negative, dtype='float32')
    Y_sensitive_negative = np.array(Y_sensitive_negative, dtype='int32')

    X_safe = np.array(X_safe, dtype='float32')
    Y_safe = np.array(Y_safe, dtype='int32')

    batch_file_vulnerable = os.path.join(CACHE_DIR, f"vulnerable_batch_{batch_index}.pkl")
    batch_file_sensitive_negative = os.path.join(CACHE_DIR, f"sensitive_negative_batch_{batch_index}.pkl")
    batch_file_safe = os.path.join(CACHE_DIR, f"safe_batch_{batch_index}.pkl")

    with open(batch_file_vulnerable, 'wb') as f:
        pickle.dump((X_vulnerable, Y_vulnerable), f)

    with open(batch_file_sensitive_negative, 'wb') as f:
        pickle.dump((X_sensitive_negative, Y_sensitive_negative), f)

    with open(batch_file_safe, 'wb') as f:
        pickle.dump((X_safe, Y_safe), f)
    print(f"Batch saved to {batch_file_vulnerable}, {batch_file_sensitive_negative}", {batch_file_safe})


def train_LSTM():
    # بارگذاری داده‌ها
    X, Y = load_batches(CACHE_DIR, file_extension=".pkl")
    print(f"Shape of X: {X.shape}")  # باید (samples, max_function_length, vector_length) باشد
    print(f"Shape of Y: {Y.shape}")  # باید (samples,) باشد
    print("Distribution in Y:", np.unique(Y, return_counts=True))

    # تقسیم داده‌ها به آموزش و تست
    X_train, X_test, Y_train, Y_test = train_test_split(X, Y, test_size=0.2, random_state=42)
    print("Distribution in Y_test:", np.unique(Y_test, return_counts=True))

    # تعریف مدل BiGRU
    model = Sequential([
        Bidirectional(GRU(128, return_sequences=True), input_shape=(X_train.shape[1], X_train.shape[2])),
        # Dropout(0.3),  # اضافه کردن Dropout برای جلوگیری از Overfitting
        Bidirectional(GRU(64)),  # یک لایه دیگر BiGRU بدون بازگشت توالی
        # Dropout(0.5),  # Dropout بیشتر برای بهبود تعمیم‌پذیری
        Dense(1, activation='sigmoid')  # لایه خروجی برای دسته‌بندی باینری
    ])

    model.compile(
        optimizer=Adam(learning_rate=0.001),
        loss="binary_crossentropy",
        metrics=['accuracy', 'Precision', 'Recall']
    )

    early_stopping = EarlyStopping(
        monitor='val_loss',  # پایش بر اساس val_loss
        patience=10,  # اگر val_loss برای 5 epoch متوالی بهبود نیافت، توقف شود
        restore_best_weights=True  # بهترین وزن‌ها را بازیابی کن
    )

    # آموزش مدل
    model.fit(
        X_train, Y_train,
        epochs=50,
        batch_size=32,
        validation_split=0,
        callbacks=[early_stopping],  # اضافه کردن Early Stopping
        verbose=2
    )
    # model.fit(
    #     X_train, Y_train,
    #     epochs=50,
    #     batch_size=32,
    #     validation_split=0.1,
    #     callbacks=[early_stopping],  # اضافه کردن Early Stopping
    #     verbose=2
    # )

    # پیش‌بینی روی داده‌های تست
    Y_pred = (model.predict(X_test) > 0.5).astype("int32")

    # محاسبه معیارها
    accuracy = accuracy_score(Y_test, Y_pred)
    report = classification_report(Y_test, Y_pred, target_names=['Safe', 'Vulnerable'], labels=[0, 1])

    print(f"Accuracy: {accuracy}")
    print("Classification Report:")
    print(report)

    # ذخیره مدل
    model.save('final_BiGRU_model.h5')
    print("Training complete with BiGRU.")

    model.save('final_model_with_focal_loss.h5')
    print("Training complete with Focal Loss.")


if __name__ == "__main__":
    files = [os.path.join(PATH, f) for f in os.listdir(PATH) if f.endswith(".sol")]
    print(f"size files {files.__len__()}")
    for batch_index, i in enumerate(range(0, len(files), batch_size)):
        batch_files = files[i:i + batch_size]
        print(f"size batch_files {batch_files.__len__()}")
        process_batch_with_categorization(batch_files, target_vulner, batch_size, batch_index)


    train_LSTM()
# 2119/2119 - 67s - 32ms/step - Precision: 0.7520 - Recall: 0.2348 - accuracy: 0.8101 - loss: 0.4412
# Epoch 2/50
# 2119/2119 - 67s - 32ms/step - Precision: 0.8185 - Recall: 0.3427 - accuracy: 0.8347 - loss: 0.3863
# Epoch 3/50
# 2119/2119 - 70s - 33ms/step - Precision: 0.7838 - Recall: 0.4112 - accuracy: 0.8418 - loss: 0.3532
# Epoch 4/50
# 2119/2119 - 70s - 33ms/step - Precision: 0.7718 - Recall: 0.4617 - accuracy: 0.8479 - loss: 0.3323
# Epoch 5/50
# 2119/2119 - 71s - 34ms/step - Precision: 0.7775 - Recall: 0.5063 - accuracy: 0.8561 - loss: 0.3162
# Epoch 6/50
# 2119/2119 - 72s - 34ms/step - Precision: 0.7790 - Recall: 0.5310 - accuracy: 0.8604 - loss: 0.3058
# Epoch 7/50
# 2119/2119 - 72s - 34ms/step - Precision: 0.7778 - Recall: 0.5594 - accuracy: 0.8647 - loss: 0.2955
# Epoch 8/50
# 2119/2119 - 73s - 35ms/step - Precision: 0.7894 - Recall: 0.5870 - accuracy: 0.8717 - loss: 0.2850
# Epoch 9/50
# 2119/2119 - 75s - 35ms/step - Precision: 0.7921 - Recall: 0.6037 - accuracy: 0.8750 - loss: 0.2791
# Epoch 10/50
# 2119/2119 - 73s - 35ms/step - Precision: 0.7962 - Recall: 0.6203 - accuracy: 0.8787 - loss: 0.2717
# Epoch 11/50
# 2119/2119 - 72s - 34ms/step - Precision: 0.8094 - Recall: 0.6414 - accuracy: 0.8852 - loss: 0.2631
# Epoch 12/50
# 2119/2119 - 70s - 33ms/step - Precision: 0.8109 - Recall: 0.6586 - accuracy: 0.8885 - loss: 0.2551
# Epoch 13/50
# 2119/2119 - 67s - 32ms/step - Precision: 0.8148 - Recall: 0.6675 - accuracy: 0.8909 - loss: 0.2505
# Epoch 14/50
# 2119/2119 - 67s - 32ms/step - Precision: 0.8200 - Recall: 0.6831 - accuracy: 0.8948 - loss: 0.2434
# Epoch 15/50
# 2119/2119 - 67s - 32ms/step - Precision: 0.8317 - Recall: 0.6947 - accuracy: 0.8995 - loss: 0.2381
# Epoch 16/50
# 2119/2119 - 69s - 32ms/step - Precision: 0.8345 - Recall: 0.7058 - accuracy: 0.9022 - loss: 0.2324
# Epoch 17/50
# 2119/2119 - 71s - 34ms/step - Precision: 0.8379 - Recall: 0.7120 - accuracy: 0.9041 - loss: 0.2276
# Epoch 18/50
# 2119/2119 - 71s - 33ms/step - Precision: 0.8444 - Recall: 0.7216 - accuracy: 0.9073 - loss: 0.2227
# Epoch 19/50
# 2119/2119 - 70s - 33ms/step - Precision: 0.8460 - Recall: 0.7271 - accuracy: 0.9087 - loss: 0.2189
# Epoch 20/50
# 2119/2119 - 70s - 33ms/step - Precision: 0.8515 - Recall: 0.7365 - accuracy: 0.9117 - loss: 0.2144
# Epoch 21/50
# 2119/2119 - 71s - 34ms/step - Precision: 0.8507 - Recall: 0.7395 - accuracy: 0.9120 - loss: 0.2116
# Epoch 22/50
# 2119/2119 - 73s - 34ms/step - Precision: 0.8608 - Recall: 0.7535 - accuracy: 0.9170 - loss: 0.2053
# Epoch 23/50
# 2119/2119 - 72s - 34ms/step - Precision: 0.8612 - Recall: 0.7519 - accuracy: 0.9168 - loss: 0.2045
# Epoch 24/50
# 2119/2119 - 74s - 35ms/step - Precision: 0.8657 - Recall: 0.7577 - accuracy: 0.9189 - loss: 0.1998
# Epoch 25/50
# 2119/2119 - 74s - 35ms/step - Precision: 0.8694 - Recall: 0.7657 - accuracy: 0.9213 - loss: 0.1960
# Epoch 26/50
# 2119/2119 - 72s - 34ms/step - Precision: 0.8716 - Recall: 0.7693 - accuracy: 0.9225 - loss: 0.1949
# Epoch 27/50
# 2119/2119 - 70s - 33ms/step - Precision: 0.8721 - Recall: 0.7701 - accuracy: 0.9227 - loss: 0.1913
# Epoch 28/50
# 2119/2119 - 71s - 34ms/step - Precision: 0.8751 - Recall: 0.7753 - accuracy: 0.9244 - loss: 0.1896
# Epoch 29/50
# 2119/2119 - 71s - 34ms/step - Precision: 0.8802 - Recall: 0.7791 - accuracy: 0.9263 - loss: 0.1856
# Epoch 30/50
# 2119/2119 - 74s - 35ms/step - Precision: 0.8804 - Recall: 0.7807 - accuracy: 0.9267 - loss: 0.1836
# Epoch 31/50
# 2119/2119 - 73s - 34ms/step - Precision: 0.8842 - Recall: 0.7809 - accuracy: 0.9276 - loss: 0.1824
# Epoch 32/50
# 2119/2119 - 71s - 34ms/step - Precision: 0.8814 - Recall: 0.7829 - accuracy: 0.9274 - loss: 0.1818
# Epoch 33/50
# 2119/2119 - 71s - 34ms/step - Precision: 0.8887 - Recall: 0.7886 - accuracy: 0.9301 - loss: 0.1777
# Epoch 34/50
# 2119/2119 - 73s - 34ms/step - Precision: 0.8892 - Recall: 0.7925 - accuracy: 0.9310 - loss: 0.1765
# Epoch 35/50
# 2119/2119 - 72s - 34ms/step - Precision: 0.8902 - Recall: 0.7932 - accuracy: 0.9314 - loss: 0.1752
# Epoch 36/50
# 2119/2119 - 72s - 34ms/step - Precision: 0.8864 - Recall: 0.7953 - accuracy: 0.9309 - loss: 0.1763
# Epoch 37/50
# 2119/2119 - 71s - 33ms/step - Precision: 0.8908 - Recall: 0.7919 - accuracy: 0.9312 - loss: 0.1754
# Epoch 38/50
# 2119/2119 - 72s - 34ms/step - Precision: 0.8945 - Recall: 0.7960 - accuracy: 0.9329 - loss: 0.1719
# Epoch 39/50
# 2119/2119 - 72s - 34ms/step - Precision: 0.8967 - Recall: 0.7967 - accuracy: 0.9335 - loss: 0.1696
# Epoch 40/50
# 2119/2119 - 68s - 32ms/step - Precision: 0.8948 - Recall: 0.7986 - accuracy: 0.9334 - loss: 0.1687
# Epoch 41/50
# 2119/2119 - 68s - 32ms/step - Precision: 0.8988 - Recall: 0.8051 - accuracy: 0.9356 - loss: 0.1681
# Epoch 42/50
# 2119/2119 - 132s - 62ms/step - Precision: 0.8957 - Recall: 0.8058 - accuracy: 0.9351 - loss: 0.1664
# Epoch 43/50
# 2119/2119 - 109s - 51ms/step - Precision: 0.8996 - Recall: 0.8049 - accuracy: 0.9358 - loss: 0.1665
# Epoch 44/50
# 2119/2119 - 65s - 31ms/step - Precision: 0.9025 - Recall: 0.8109 - accuracy: 0.9376 - loss: 0.1627
# Epoch 45/50
# 2119/2119 - 67s - 32ms/step - Precision: 0.8998 - Recall: 0.8075 - accuracy: 0.9364 - loss: 0.1634
# Epoch 46/50
# 2119/2119 - 176s - 83ms/step - Precision: 0.9022 - Recall: 0.8090 - accuracy: 0.9372 - loss: 0.1614
# Epoch 47/50
# 2119/2119 - 115s - 54ms/step - Precision: 0.9025 - Recall: 0.8110 - accuracy: 0.9377 - loss: 0.1614
# Epoch 48/50
# 2119/2119 - 186s - 88ms/step - Precision: 0.9045 - Recall: 0.8093 - accuracy: 0.9378 - loss: 0.1615
# Epoch 49/50
# 2119/2119 - 159s - 75ms/step - Precision: 0.9058 - Recall: 0.8124 - accuracy: 0.9387 - loss: 0.1586
# Epoch 50/50
# 2119/2119 - 88s - 41ms/step - Precision: 0.9013 - Recall: 0.8106 - accuracy: 0.9373 - loss: 0.1618
# 530/530 ━━━━━━━━━━━━━━━━━━━━ 6s 11ms/step
# Accuracy: 0.9004661041949378
# Classification Report:
#               precision    recall  f1-score   support
#
#         Safe       0.92      0.96      0.94     13127
#   Vulnerable       0.83      0.70      0.76      3822
#
#     accuracy                           0.90     16949
#    macro avg       0.87      0.83      0.85     16949
# weighted avg       0.90      0.90      0.90     16949

