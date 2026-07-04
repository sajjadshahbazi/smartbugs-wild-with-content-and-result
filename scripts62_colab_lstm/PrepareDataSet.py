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
import pickle
import PreProcessTools
import numpy as np
import io
from tensorflow.keras import backend as K
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
from tensorflow.keras.models import Sequential
# from tensorflow.keras.layers import Conv1D, Bidirectional, LSTM, Dropout, Dense
from tensorflow.keras.layers import Embedding, Bidirectional, LSTM, Dropout, Dense
from tensorflow.keras.callbacks import EarlyStopping
from tensorflow.keras.optimizers import Adam
import tensorflow as tf
from tensorflow.python.platform import build_info as tf_build_info
from tensorflow.keras.layers import Input
import matplotlib.pyplot as plt

# =============================================================================
# اضافه شد (بدون تغییر در import های بالا): این importها فقط برای بخش
# جدید U-Net + BiLSTM لازم هستند و به هیچ‌کدام از importهای موجود
# دست نخورده است.
# =============================================================================
from tensorflow.keras.layers import Conv2D, MaxPooling2D, UpSampling2D, concatenate, Flatten
from tensorflow.keras.models import Model

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

# =============================================================================
# اصلاح ۱: sequence_length از 10 به 100 تغییر یافت
# دلیل: مقاله بخش ۳.۳ می‌گوید اندازه ماتریس embedding برابر (300, 100)
# است. یعنی هر function به 100 توکن با بردار 300 بعدی تبدیل می‌شود.
# با مقدار 10، اکثر اطلاعات توابع از دست می‌رفت.
# =============================================================================
sequence_length = 100  # اصلاح شد: از 10 به 100

# =============================================================================
# اضافه شد: co_occurrence_window برای ساخت Attention Map
# این پارامتر فقط برای بخش جدید U-Net استفاده می‌شود و بخشی از مقاله
# پایه نیست - برای پیاده‌سازی روش Attention Map که قبلاً بحث کردیم لازم است.
# =============================================================================
co_occurrence_window = 3

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

ROOT = '/content/smartbugs-wild-with-content-and-result' # Linux
CACHE_DIR = os.path.join(ROOT, 'vectorcollections') # Linux

# ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), '..'))
# CACHE_DIR = os.path.join(ROOT, 'vectorcollections')

# =============================================================================
# اضافه شد: مسیر جدا برای دیتاست U-Net + BiLSTM
# دلیل: طبق درخواست شما، دیتاست LSTM تنها باید در همان vectorcollections
# باقی بماند (بدون تغییر) و دیتاست ترکیبی U-Net+BiLSTM باید در یک مسیر
# کاملاً جدا ذخیره شود تا با هم قاطی نشوند.
# =============================================================================
CACHE_DIR_UNET = os.path.join(ROOT, 'vectorcollections_img')



cache_path = os.path.join(CACHE_DIR, 'tokenized_fragments.pkl')
vulnerability_fd = open(os.path.join(ROOT, 'metadata', 'vulnerabilities.csv'), 'w', encoding='utf-8')

# PATH = f"{ROOT}\\contracts\\"  # main data set
# PATH = f"{ROOT}\\contract\\"  # part of main data set
# PATH = f"{ROOT}\\contra\\"  # one smart contract

PATH = os.path.join(ROOT, 'contracts') # linux
os.chdir(PATH)

final_df = pd.DataFrame(columns=['X', 'Y'])


# =============================================================================
# اصلاح ۲: focal_loss جایگزین binary_crossentropy شد
# دلیل: مقاله بخش ۳.۴ صراحتاً focal_loss با alpha=0.25 و gamma=2
# را برای حل مشکل عدم توازن کلاس‌ها استفاده می‌کند.
# در dataset این پروژه هم عدم توازن بین vulnerable و safe وجود دارد.
# =============================================================================
def focal_loss(alpha=0.25, gamma=2.0):
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


def getResultVulnarable(contract_name, target_vulnerability):

    total_duration = 0
    res = False
    lines = []
    for tool in tools:
        path_result = os.path.join(f"{ROOT}\\results\\", tool, output_name, contract_name, 'result.json')
        # path_result = os.path.join(f"{ROOT}results", tool, output_name, contract_name, 'result.json') # Linux
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
    ورودی: همه توکن‌های یک function (نه یک fragment)
    خروجی: آرایه دو‌بعدی (sequence_length × vector_length)
    """
    # ایجاد مدل Word2Vec روی همه توکن‌های یک function
    word2vec_model = Word2Vec(sentences=[tokens], vector_size=vector_length, window=5, min_count=1, workers=4)

    # تبدیل توکن‌ها به بردارهای Word2Vec
    embeddings = [
        word2vec_model.wv[word] if word in word2vec_model.wv else np.zeros(vector_length)
        for word in tokens
    ]

    # اعمال padding یا truncate به sequence_length=100
    embeddings = embeddings[:sequence_length] + [np.zeros(vector_length)] * max(0, sequence_length - len(embeddings))

    # تبدیل به آرایه NumPy
    return np.array(embeddings, dtype='float32')


# =============================================================================
# اضافه شد: create_attention_map
# این تابع جدید است و بخشی از مقاله پایه نیست - پیاده‌سازی روش
# Attention Map که قبلاً با هم بحث کردیم (ترکیب similarity matrix
# و co-occurrence matrix).
#
# ورودی: embedding_matrix با شکل (sequence_length, vector_length)
#         real_token_count = تعداد توکن‌های واقعی قبل از padding
# خروجی: ماتریس (sequence_length, sequence_length, 1) برای U-Net
#
# روش کار:
#   ۱. similarity_matrix = شباهت cosine بین همه جفت توکن‌ها
#      (بردارهای padding صفر هستند، پس شباهتشان صفر می‌شود - بی‌اثر)
#   ۲. co_occurrence_matrix = آیا دو توکن در فاصله co_occurrence_window
#      از هم قرار دارند (1) یا نه (0) - فقط بین توکن‌های واقعی
#   ۳. attention_map = similarity_matrix * co_occurrence_matrix
# =============================================================================
def create_attention_map(embedding_matrix, real_token_count, window=co_occurrence_window):
    """
    :param embedding_matrix: آرایه (sequence_length, vector_length) - خروجی vectorize_tokens
    :param real_token_count: تعداد توکن‌های واقعی قبل از padding
    :param window: اندازه پنجره co-occurrence
    :return: آرایه (sequence_length, sequence_length, 1)
    """
    # مرحله ۱: similarity matrix با cosine similarity
    norms = np.linalg.norm(embedding_matrix, axis=1, keepdims=True)
    norms[norms == 0] = 1e-10  # جلوگیری از تقسیم بر صفر برای بردارهای padding
    normalized = embedding_matrix / norms
    similarity_matrix = np.dot(normalized, normalized.T)  # (seq_len, seq_len)

    # مرحله ۲: co-occurrence matrix - فقط بین توکن‌های واقعی
    seq_len = embedding_matrix.shape[0]
    co_matrix = np.zeros((seq_len, seq_len), dtype='float32')
    limit = min(real_token_count, seq_len)
    for idx in range(limit):
        for w in range(1, window + 1):
            if idx + w < limit:
                co_matrix[idx][idx + w] = 1.0
                co_matrix[idx + w][idx] = 1.0

    # مرحله ۳: ترکیب - ضرب عنصر به عنصر
    attention_map = similarity_matrix * co_matrix  # (seq_len, seq_len)

    # مرحله ۴: اضافه کردن بعد channel برای Conv2D در U-Net
    attention_map = attention_map.reshape(seq_len, seq_len, 1)

    return attention_map.astype('float32')


def label_functions_by_vulnerable_lines(functions, vulnerable_lines):
    for func in functions:
        if any(func['start_line'] <= line <= func['end_line'] for line in vulnerable_lines):
            func['label'] = 1  # اگر خط آسیب‌پذیر در فانکشن باشد، لیبل ۱ می‌شود


def process_batch_with_categorization(files, target_vulnerability, batch_size, batch_index):
    X_sensitive_negative, Y_sensitive_negative = [], []
    X_vulnerable, Y_vulnerable = [], []
    X_safe, Y_safe = [], []

    # =============================================================================
    # اصلاح ۳: max_function_length از 50 به 100 تغییر یافت
    # دلیل: باید با sequence_length=100 یکسان باشد.
    # مقاله ماتریس (100, 300) را برای هر function در نظر دارد.
    # با مقدار 50، نیمی از اطلاعات بردارها در pad_sequences قطع می‌شد.
    # =============================================================================
    max_function_length = 100  # اصلاح شد: از 50 به 100

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

                # =====================================================================
                # اصلاح ۴: جمع‌آوری همه توکن‌های یک function در یک لیست واحد
                # قبلاً: هر fragment جداگانه vectorize می‌شد و بردارها extend می‌شدند
                #   → Word2Vec فقط context یک خط را می‌دید
                # اکنون: ابتدا همه توکن‌های همه fragmentها جمع می‌شوند
                #         سپس یک‌بار vectorize_tokens فراخوانی می‌شود
                #   → Word2Vec context کل function را می‌بیند
                # =====================================================================
                all_tokens = []
                for fragment in fragments:
                    if fragment.strip():
                        tokens = tokenize_solidity_code(fragment)
                        if tokens:
                            all_tokens.extend(tokens)  # جمع‌آوری همه توکن‌ها

                if all_tokens:
                    # یک‌بار vectorize روی همه توکن‌های function
                    func_vectors = vectorize_tokens(all_tokens)
                    # func_vectors شکل (sequence_length=100, vector_length=300) دارد
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


# =============================================================================
# اضافه شد: load_batches_by_prefix
# دلیل: تابع load_batches موجود دست‌نخورده باقی مانده (برای train_LSTM).
# این تابع جدید و جداگانه است، فقط برای بخش U-Net لازم است تا بتوانیم
# فایل‌های embedding (پیشوند emb_) و attention map (پیشوند att_) را
# جداگانه از هم بارگذاری کنیم، چون در یک پوشه (CACHE_DIR_UNET) کنار هم
# ذخیره می‌شوند.
# =============================================================================
# def load_batches_by_prefix(folder, prefix, file_extension=".pkl"):
#     X_batches, Y_batches = [], []
#     for file in os.listdir(folder):
#         if file.endswith(file_extension) and file.startswith(prefix):
#             with open(os.path.join(folder, file), 'rb') as f:
#                 X, Y = pickle.load(f)
#                 X_batches.append(X)
#                 Y_batches.append(Y)
#     return np.vstack(X_batches), np.hstack(Y_batches)

# Sorted
def load_batches_by_prefix(folder, prefix, file_extension=".pkl"):
    X_batches, Y_batches = [], []
    matched_files = sorted([
        f for f in os.listdir(folder)
        if f.endswith(file_extension) and f.startswith(prefix)
    ])
    for file in matched_files:
        with open(os.path.join(folder, file), 'rb') as f:
            X, Y = pickle.load(f)
            X_batches.append(X)
            Y_batches.append(Y)
    return np.vstack(X_batches), np.hstack(Y_batches)


# =============================================================================
# اضافه شد: process_batch_with_categorization_for_unet
# این یک تابع کاملاً جدید و جداگانه است - تابع اصلی
# process_batch_with_categorization بالا هیچ تغییری نکرده است.
#
# تفاوت با تابع اصلی:
#   - برای هر function، هم embedding matrix (100,300) هم
#     attention_map (100,100,1) ساخته می‌شود
#   - همه چیز در CACHE_DIR_UNET (پوشه vectorcollections_img) ذخیره می‌شود
#     نه در CACHE_DIR (vectorcollections) که مخصوص LSTM تنها است
#   - فایل‌های embedding با پیشوند emb_ و فایل‌های attention map با
#     پیشوند att_ ذخیره می‌شوند تا در train_UNET_LSTM جدا از هم لود شوند
#
# منطق labeling (getResultVulnarable) و contains_sensitive_operator
# دقیقاً همان چیزی است که در تابع اصلی است - هیچ تغییری نکرده.
# =============================================================================
def process_batch_with_categorization_for_unet(files, target_vulnerability, batch_size, batch_index):
    X_sensitive_negative_emb, X_sensitive_negative_att, Y_sensitive_negative = [], [], []
    X_vulnerable_emb, X_vulnerable_att, Y_vulnerable = [], [], []
    X_safe_emb, X_safe_att, Y_safe = [], [], []

    max_function_length = 100  # همانند تابع اصلی - مطابق sequence_length=100

    sc_files = [f for f in files if f.endswith(".sol")]
    print(f"cont {sc_files.__len__()}")
    for file in sc_files:
        with (open(file, encoding="utf8") as f):
            contract_content = f.read()

            functions = extract_functions_with_bodies(contract_content)
            name = Path(file).stem
            res, vulnerable_lines = getResultVulnarable(name, target_vulnerability)

            label_functions_by_vulnerable_lines(functions, vulnerable_lines)
            for func in functions:
                fragments = PreProcessTools.get_fragments(func['function_body'])
                label = func['label']

                # جمع‌آوری همه توکن‌های یک function - همانند تابع اصلی
                all_tokens = []
                for fragment in fragments:
                    if fragment.strip():
                        tokens = tokenize_solidity_code(fragment)
                        if tokens:
                            all_tokens.extend(tokens)

                if all_tokens:
                    # embedding برای شاخه BiLSTM
                    func_vectors = vectorize_tokens(all_tokens)
                    padded_function = pad_sequences(
                        [func_vectors], maxlen=max_function_length, padding='post', dtype='float32'
                    )[0]

                    # attention map برای شاخه U-Net
                    real_token_count = min(len(all_tokens), sequence_length)
                    att_map = create_attention_map(padded_function, real_token_count)

                    if label == 1:
                        X_vulnerable_emb.append(padded_function)
                        X_vulnerable_att.append(att_map)
                        Y_vulnerable.append(label)
                    else:
                        if contains_sensitive_operator(func['function_body']):
                            X_sensitive_negative_emb.append(padded_function)
                            X_sensitive_negative_att.append(att_map)
                            Y_sensitive_negative.append(label)
                        else:
                            X_safe_emb.append(padded_function)
                            X_safe_att.append(att_map)
                            Y_safe.append(label)

    def _to_arrays(x_emb, x_att, y):
        return (
            np.array(x_emb, dtype='float32'),
            np.array(x_att, dtype='float32'),
            np.array(y, dtype='int32')
        )

    X_vulnerable_emb, X_vulnerable_att, Y_vulnerable = _to_arrays(X_vulnerable_emb, X_vulnerable_att, Y_vulnerable)
    X_sensitive_negative_emb, X_sensitive_negative_att, Y_sensitive_negative = _to_arrays(
        X_sensitive_negative_emb, X_sensitive_negative_att, Y_sensitive_negative)
    X_safe_emb, X_safe_att, Y_safe = _to_arrays(X_safe_emb, X_safe_att, Y_safe)

    os.makedirs(CACHE_DIR_UNET, exist_ok=True)

    # ذخیره embedding (برای شاخه BiLSTM) - پیشوند emb_
    with open(os.path.join(CACHE_DIR_UNET, f"emb_vulnerable_batch_{batch_index}.pkl"), 'wb') as f:
        pickle.dump((X_vulnerable_emb, Y_vulnerable), f)
    with open(os.path.join(CACHE_DIR_UNET, f"emb_sensitive_negative_batch_{batch_index}.pkl"), 'wb') as f:
        pickle.dump((X_sensitive_negative_emb, Y_sensitive_negative), f)
    with open(os.path.join(CACHE_DIR_UNET, f"emb_safe_batch_{batch_index}.pkl"), 'wb') as f:
        pickle.dump((X_safe_emb, Y_safe), f)

    # ذخیره attention map (برای شاخه U-Net) - پیشوند att_
    with open(os.path.join(CACHE_DIR_UNET, f"att_vulnerable_batch_{batch_index}.pkl"), 'wb') as f:
        pickle.dump((X_vulnerable_att, Y_vulnerable), f)
    with open(os.path.join(CACHE_DIR_UNET, f"att_sensitive_negative_batch_{batch_index}.pkl"), 'wb') as f:
        pickle.dump((X_sensitive_negative_att, Y_sensitive_negative), f)
    with open(os.path.join(CACHE_DIR_UNET, f"att_safe_batch_{batch_index}.pkl"), 'wb') as f:
        pickle.dump((X_safe_att, Y_safe), f)

    print(f"Batch {batch_index} saved in {CACHE_DIR_UNET}: embedding (emb_) + attention_map (att_) files")


# =============================================================================
# اضافه شد: build_unet_branch
# شاخه U-Net که روی attention_map (100,100,1) کار می‌کند.
# معماری بر اساس همان الگوی U-Net معمول (encoder-decoder با skip
# connection) است.
# =============================================================================
def build_unet_branch(input_shape):
    inputs = Input(shape=input_shape, name='attention_map_input')

    # Encoder
    conv1 = Conv2D(64, (3, 3), activation='relu', padding='same')(inputs)
    pool1 = MaxPooling2D((2, 2))(conv1)

    conv2 = Conv2D(128, (3, 3), activation='relu', padding='same')(pool1)
    pool2 = MaxPooling2D((2, 2))(conv2)

    # Bottleneck
    conv3 = Conv2D(256, (3, 3), activation='relu', padding='same')(pool2)

    # Decoder
    up1 = UpSampling2D((2, 2))(conv3)
    concat1 = concatenate([conv2, up1])
    conv4 = Conv2D(128, (3, 3), activation='relu', padding='same')(concat1)

    up2 = UpSampling2D((2, 2))(conv4)
    concat2 = concatenate([conv1, up2])
    conv5 = Conv2D(64, (3, 3), activation='relu', padding='same')(concat2)

    flat = Flatten()(conv5)
    dense_out = Dense(128, activation='relu')(flat)

    return inputs, dense_out


# =============================================================================
# اضافه شد: build_bilstm_branch
# شاخه BiLSTM که روی embedding matrix (100,300) کار می‌کند.
# معماری همان معماری train_LSTM موجود است (بدون تغییر منطق آن تابع).
# =============================================================================
def build_bilstm_branch(input_shape):
    inputs = Input(shape=input_shape, name='embedding_input')
    x = Bidirectional(LSTM(128, return_sequences=True))(inputs)
    x = Dropout(0.5)(x)
    x = Bidirectional(LSTM(64))(x)
    return inputs, x


# =============================================================================
# اضافه شد: build_unet_bilstm_model
# ترکیب دو شاخه: U-Net (attention_map) + BiLSTM (embedding)
# خروجی: احتمال آسیب‌پذیری با sigmoid
# =============================================================================
def build_unet_bilstm_model(seq_len=sequence_length, vec_len=vector_length):
    unet_input, unet_output = build_unet_branch((seq_len, seq_len, 1))
    lstm_input, lstm_output = build_bilstm_branch((seq_len, vec_len))

    combined = concatenate([unet_output, lstm_output])
    dense1 = Dense(128, activation='relu')(combined)
    dense2 = Dense(64, activation='relu')(dense1)
    outputs = Dense(1, activation='sigmoid')(dense2)

    model = Model(inputs=[unet_input, lstm_input], outputs=outputs)
    return model


# =============================================================================
# اضافه شد: train_UNET_LSTM
# تابع آموزش جدید و جداگانه برای مدل ترکیبی U-Net(Attention Map) + BiLSTM.
# تابع train_LSTM موجود هیچ تغییری نکرده و برای اجرای LSTM تنها باقی مانده.
# =============================================================================
def train_UNET_LSTM():
    # بارگذاری دو نوع داده جداگانه از CACHE_DIR_UNET با پیشوند متفاوت
    X_att, Y_att = load_batches_by_prefix(CACHE_DIR_UNET, prefix="att_")
    X_emb, Y_emb = load_batches_by_prefix(CACHE_DIR_UNET, prefix="emb_")

    print(f"Shape of X_att (attention map): {X_att.shape}")
    print(f"Shape of X_emb (embedding): {X_emb.shape}")
    print(f"Shape of Y: {Y_att.shape}")

    # اطمینان از یکسان بودن ترتیب لیبل‌ها بین دو نوع داده
    assert np.array_equal(Y_att, Y_emb), "ترتیب Y بین att و emb یکسان نیست - فایل‌ها را بررسی کنید"

    print("Distribution in Y:", np.unique(Y_att, return_counts=True))

    indices = np.arange(len(Y_att))
    train_idx, test_idx = train_test_split(indices, test_size=0.2, random_state=42)

    X_att_train, X_att_test = X_att[train_idx], X_att[test_idx]
    X_emb_train, X_emb_test = X_emb[train_idx], X_emb[test_idx]
    Y_train, Y_test = Y_att[train_idx], Y_att[test_idx]

    print("Distribution in Y_test:", np.unique(Y_test, return_counts=True))

    model = build_unet_bilstm_model()

    model.compile(
        optimizer=Adam(learning_rate=0.001),
        loss=focal_loss(alpha=0.25, gamma=2.0),
        metrics=['accuracy']
    )

    model.summary()

    early_stopping = EarlyStopping(
        monitor='val_loss',
        patience=10,
        restore_best_weights=True
    )

    history = model.fit(
        [X_att_train, X_emb_train], Y_train,
        epochs=50,
        batch_size=128,
        validation_split=0.2,
        callbacks=[early_stopping],
        verbose=2
    )

    plt.figure(figsize=(10, 6))
    plt.plot(history.history['accuracy'], label='train acc', color='blue')
    plt.plot(history.history['val_accuracy'], label='val acc', color='yellow')
    plt.plot(history.history['loss'], label='train loss', color='red')
    plt.plot(history.history['val_loss'], label='val loss', color='green')
    plt.title('U-Net(AttentionMap) + BiLSTM - Accuracy and Loss')
    plt.xlabel('Epochs')
    plt.ylabel('Accuracy / Loss')
    plt.legend(loc='best')
    plt.grid()

    output_image_path = "training_plot_unet_attention_lstm.png"
    plt.savefig(output_image_path, dpi=300, bbox_inches='tight')
    print(f"Plot saved to {output_image_path}")
    plt.show()

    Y_pred = (model.predict([X_att_test, X_emb_test]) > 0.5).astype("int32")

    accuracy = accuracy_score(Y_test, Y_pred)
    report = classification_report(Y_test, Y_pred, target_names=['Safe', 'Vulnerable'], labels=[0, 1])

    print(f"Accuracy: {accuracy}")
    print("Classification Report:")
    print(report)

    model.save('final_unet_attention_lstm_model.h5')
    print("Training complete with U-Net(AttentionMap) + BiLSTM.")


def train_LSTM():
    # بارگذاری داده‌ها
    X, Y = load_batches(CACHE_DIR, file_extension=".pkl")
    print(f"Shape of X: {X.shape}")  # باید (samples, max_function_length, vector_length) باشد
    print(f"Shape of Y: {Y.shape}")  # باید (samples,) باشد
    print("Distribution in Y:", np.unique(Y, return_counts=True))

    # تقسیم داده‌ها به آموزش و تست
    X_train, X_test, Y_train, Y_test = train_test_split(X, Y, test_size=0.2, random_state=42)
    print("Distribution in Y_test:", np.unique(Y_test, return_counts=True))

    # =============================================================================
    # اصلاح ۵: اضافه شدن Dropout به معماری مدل
    # دلیل: مقاله بخش ۴ می‌گوید 'dropout set to 0.5'
    # Dropout از overfitting جلوگیری می‌کند.
    # =============================================================================
    model = Sequential([
        Input(shape=(X_train.shape[1], X_train.shape[2])),
        Bidirectional(LSTM(128, return_sequences=True)),
        Dropout(0.5),
        Bidirectional(LSTM(64)),
        Dense(1, activation='sigmoid')
    ])

    # =============================================================================
    # اصلاح ۶: loss از binary_crossentropy به focal_loss تغییر یافت
    # دلیل: مقاله بخش ۳.۴ صراحتاً focal_loss با alpha=0.25 و gamma=2
    # را مشخص کرده است. focal_loss برای dataset‌های نامتوازن بهتر است.
    # =============================================================================
    model.compile(
        optimizer=Adam(learning_rate=0.001),
        loss=focal_loss(alpha=0.25, gamma=2.0),  # اصلاح شد: از binary_crossentropy به focal_loss
        metrics=['accuracy']
    )

    early_stopping = EarlyStopping(
        monitor='val_loss',  # پایش بر اساس val_loss
        patience=10,  # اگر val_loss برای 10 epoch متوالی بهبود نیافت، توقف شود
        restore_best_weights=True  # بهترین وزن‌ها را بازیابی کن
    )

    # =============================================================================
    # اصلاح ۷: batch_size از 32 به 128 تغییر یافت
    # دلیل: مقاله بخش ۴ صراحتاً می‌گوید 'batch size to 128'
    # =============================================================================
    history = model.fit(
        X_train, Y_train,
        epochs=50,
        batch_size=128,     # اصلاح شد: از 32 به 128 مطابق مقاله
        validation_split=0.2,
        callbacks=[early_stopping],  # اضافه کردن Early Stopping
        verbose=2
    )

    # ذخیره در پوشه output داخل مسیر پروژه
    os.makedirs(os.path.join(ROOT, 'output'), exist_ok=True)

    # رسم نمودار دقت و خطا
    plt.figure(figsize=(10, 6))

    # رسم دقت
    plt.plot(history.history['accuracy'], label='train acc', color='blue')
    plt.plot(history.history['val_accuracy'], label='val acc', color='yellow')

    # رسم خطا
    plt.plot(history.history['loss'], label='train loss', color='red')
    plt.plot(history.history['val_loss'], label='val loss', color='green')

    plt.title('Model Accuracy and Loss')
    plt.xlabel('Epochs')
    plt.ylabel('Accuracy / Loss')
    plt.legend(loc='best')
    plt.grid()

    output_image_path = os.path.join(ROOT, 'output', 'training_plot_lstm.png')
    plt.savefig(output_image_path, dpi=300, bbox_inches='tight')
    print(f"Plot saved to {output_image_path}")

    plt.show()

    # پیش‌بینی روی داده‌های تست
    Y_pred = (model.predict(X_test) > 0.5).astype("int32")

    # محاسبه معیارها
    accuracy = accuracy_score(Y_test, Y_pred)
    report = classification_report(Y_test, Y_pred, target_names=['Safe', 'Vulnerable'], labels=[0, 1])

    print(f"Accuracy: {accuracy}")
    print("Classification Report:")
    print(report)

    # ذخیره مدل
    model.save(os.path.join(ROOT, 'output', 'final_LSTM_model.h5'))

    print("Training complete with LSTM.")




if __name__ == "__main__":
    files = [os.path.join(PATH, f) for f in os.listdir(PATH) if f.endswith(".sol")]
    print(f"size files {files.__len__()}")

    # =============================================================================
    # تغییر: طبق درخواست شما، در همین اجرای اول، دیتاست هر دو حالت
    # (LSTM تنها و U-Net+BiLSTM) در یک حلقه ساخته می‌شوند:
    #   - process_batch_with_categorization      → ذخیره در vectorcollections/
    #   - process_batch_with_categorization_for_unet → ذخیره در vectorcollections_img/
    # این دو تابع کاملاً مستقل از هم هستند و در دو مسیر جدا ذخیره می‌کنند،
    # پس هیچ تداخلی با هم ندارند.
    # =============================================================================
    # for batch_index, i in enumerate(range(0, len(files), batch_size)):
    #     batch_files = files[i:i + batch_size]
    #     print(f"size batch_files {batch_files.__len__()}")
    #     process_batch_with_categorization(batch_files, target_vulner, batch_size, batch_index)
    #     process_batch_with_categorization_for_unet(batch_files, target_vulner, batch_size, batch_index)

    # =============================================================================
    # بخش آموزش: طبق درخواست شما این دو به صورت جدا و در دو اجرای متفاوت
    # فراخوانی می‌شوند - نه همزمان. یعنی:
    #   ۱. ابتدا فقط train_LSTM() را از کامنت خارج کنید و اجرا کنید،
    #      نتیجه را بردارید.
    #   ۲. سپس train_LSTM() را دوباره کامنت کنید و train_UNET_LSTM() را
    #      از کامنت خارج کنید و دوباره اجرا کنید.
    # چون دیتاست هر دو از قبل (در همین اجرای بالا) آماده شده، هر بار فقط
    # کافی است تابع train مربوطه را از کامنت خارج کنید - نیازی به ساخت
    # دوباره دیتاست نیست.
    # =============================================================================
    # train_LSTM()
    train_UNET_LSTM()


