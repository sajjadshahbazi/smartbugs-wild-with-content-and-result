import json
import re
import os
from pathlib import Path
from imblearn.over_sampling import SMOTE
import pandas as pd
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.utils import Sequence
from tensorflow.keras.models import load_model

import sys
from gensim.models import Word2Vec
# =============================================================================
# اضافه شد: import FastText
# طبق درخواست شما، فقط برای آماده‌سازی داده‌ی attention map شاخه‌ی U-Net
# استفاده می‌شود. import های موجود (از جمله Word2Vec) دست‌نخورده باقی مانده‌اند.
# =============================================================================
from gensim.models import FastText
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
from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau, ModelCheckpoint
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
# =============================================================================
# اصلاح ۹ (بازبینی‌شده): BatchNormalization ابتدا اضافه شد ولی چون در آزمایش
# واقعی باعث ناپایداری و افت شدید دقت شد (نگاه کنید به کامنت داخل
# build_unet_branch)، از import ها حذف شد و فقط GlobalMaxPooling2D
# (اصلاح ۱۲) اضافه شده است.
# =============================================================================
from tensorflow.keras.layers import Conv2D, MaxPooling2D, UpSampling2D, concatenate, Flatten, SpatialDropout2D
from tensorflow.keras.layers import GlobalAveragePooling2D, GlobalMaxPooling2D
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

ROOT = '/content/smartbugs-wild-with-content-and-result'  # Linux
CACHE_DIR = os.path.join(ROOT, 'vectorcollections')  # Linux

# ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), '..'))
# CACHE_DIR = os.path.join(ROOT, 'vectorcollections')

# =============================================================================
# اضافه شد: مسیر جدا برای دیتاست U-Net + BiLSTM
# دلیل: طبق درخواست شما، دیتاست LSTM تنها باید در همان vectorcollections
# باقی بماند (بدون تغییر) و دیتاست ترکیبی U-Net+BiLSTM باید در یک مسیر
# کاملاً جدا ذخیره شود تا با هم قاطی نشوند.
# =============================================================================
CACHE_DIR_UNET = os.path.join(ROOT, 'vectorcollections_img')

# =============================================================================
# اضافه شد: مسیر مدل FastText سراسری (Global)
# دلیل: وقتی به ازای هر function یک FastText جداگانه می‌سازیم، هر توکن فقط
# context همان یک function را می‌بیند. با یک مدل سراسری، تمام توابع در یک
# فضای برداری یکپارچه قرار می‌گیرند و U-Net می‌تواند الگوهای معنایی پایدار
# (مثل call.value) را بین نمونه‌های مختلف generalize کند.
# =============================================================================
GLOBAL_FASTTEXT_PATH = os.path.join(ROOT, 'global_fasttext_model.bin')

# =============================================================================
# اضافه شد: مسیر مدل Word2Vec سراسری (Global) - برای شاخه BiLSTM
# دلیل: دقیقاً همان مشکل GLOBAL_FASTTEXT_PATH برای شاخه U-Net، اینجا هم
# برای شاخه BiLSTM صدق می‌کند. با یک مدل سراسری، هر دو شاخه (U-Net و
# BiLSTM) در یک فضای برداری یکپارچه قرار می‌گیرند.
# =============================================================================
GLOBAL_WORD2VEC_PATH = os.path.join(ROOT, 'global_word2vec_model.bin')

cache_path = os.path.join(CACHE_DIR, 'tokenized_fragments.pkl')
vulnerability_fd = open(os.path.join(ROOT, 'metadata', 'vulnerabilities.csv'), 'w', encoding='utf-8')

# PATH = f"{ROOT}\\contracts\\"  # main data set
# PATH = f"{ROOT}\\contract\\"  # part of main data set
# PATH = f"{ROOT}\\contra\\"  # one smart contract

PATH = os.path.join(ROOT, 'contracts')  # Linux
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
        # path_result = os.path.join(f"{ROOT}\\results\\", tool, output_name, contract_name, 'result.json')
        path_result = os.path.join(f"{ROOT}results", tool, output_name, contract_name, 'result.json')  # Linux
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
        if re.match(r'[a-zA-Z_][a-zA-Z0-9_]*', token) and token not in ['function', 'returns', 'internal', 'constant',
                                                                        'assert', 'return']:
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


def vectorize_tokens(tokens, global_model=None):
    """
    تبدیل یک لیست از توکن‌ها به آرایه‌ای از بردارهای ویژگی.
    ورودی: همه توکن‌های یک function (نه یک fragment)
    خروجی: آرایه دو‌بعدی (sequence_length × vector_length)

    # =========================================================================
    # اصلاح: پشتیبانی از مدل Word2Vec سراسری (Global) - برای شاخه BiLSTM
    # دلیل: دقیقاً همان دلیل vectorize_tokens_fasttext برای شاخه U-Net.
    # اولویت با مدل سراسری (global) اگر موجود باشد. در صورت عدم وجود،
    # به حالت قبلی (محلی per-function) fallback می‌کند تا سازگاری با کد
    # قبلی (و با فراخوانی‌های موجود بدون آرگومان global_model) حفظ شود.
    # =========================================================================
    """
    if global_model is not None:
        # استفاده از مدل سراسری که از بیرون پاس داده شده
        embeddings = [
            global_model.wv[word] if word in global_model.wv else np.zeros(vector_length)
            for word in tokens
        ]
    elif os.path.exists(GLOBAL_WORD2VEC_PATH):
        # لود مدل سراسری اگر قبلاً ساخته شده (fallback خودکار)
        loaded_model = Word2Vec.load(GLOBAL_WORD2VEC_PATH)
        embeddings = [
            loaded_model.wv[word] if word in loaded_model.wv else np.zeros(vector_length)
            for word in tokens
        ]
    else:
        # Fallback به حالت قبلی (محلی per-function) - همان رفتار قبل
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
# اضافه شد: build_global_fasttext_model
# یکبار اجرا می‌شود (یا لود می‌شود اگر قبلاً ساخته شده).
# روی نمونه‌ای از کل corpus آموزش می‌بیند تا vocabulary مشترک ایجاد کند.
# =============================================================================
def build_global_fasttext_model(max_contracts=15000):
    """
    آموزش یک مدل FastText سراسری روی نمونه‌ای از کل corpus.

    دلیل:
    وقتی به ازای هر function یک FastText جداگانه می‌سازیم، بردار یک توکن
    مشابه (مثلاً 'call') در دو function متفاوت، بردارهای کاملاً متفاوتی
    می‌گیرد چون context هر function محدود است. این باعث می‌شود U-Net
    نتواند الگوهای ثابتی مثل «call.value» یا «require(msg.sender» را
    بین نمونه‌های مختلف generalize کند.

    با یک مدل سراسری، تمام توابع در یک فضای برداری یکپارچه قرار می‌گیرند
    و شبکه می‌تواند روابط معنایی پایدار را یاد بگیرد.
    """
    all_tokens_global = []
    files = [os.path.join(PATH, f) for f in os.listdir(PATH) if f.endswith(".sol")]

    # محدود کردن برای سرعت - حتی 15000 قرارداد کافی است برای پوشش vocabulary
    if len(files) > max_contracts:
        import random
        random.seed(42)
        files = random.sample(files, max_contracts)

    print(f"Building global FastText corpus from {len(files)} contracts...")

    for file_idx, file in enumerate(files):
        if file_idx % 1000 == 0:
            print(f"  Processed {file_idx}/{len(files)} contracts...")
        try:
            with open(file, encoding="utf8") as f:
                contract_content = f.read()
        except Exception:
            continue

        functions = extract_functions_with_bodies(contract_content)
        for func in functions:
            fragments = PreProcessTools.get_fragments(func['function_body'])
            func_tokens = []
            for fragment in fragments:
                if fragment.strip():
                    tokens = tokenize_solidity_code(fragment)
                    if tokens:
                        func_tokens.extend(tokens)
            if func_tokens:
                all_tokens_global.append(func_tokens)

    print(f"Training global FastText on {len(all_tokens_global)} functions...")
    global_model = FastText(
        sentences=all_tokens_global,
        vector_size=vector_length,
        window=5,
        min_count=1,
        workers=4,
        sg=0,
        bucket=50000  # بزرگتر چون vocabulary کل corpus است
    )
    global_model.save(GLOBAL_FASTTEXT_PATH)
    print(f"Global FastText saved to {GLOBAL_FASTTEXT_PATH}")
    print(f"Vocabulary size: {len(global_model.wv)}")
    return global_model


# =============================================================================
# اضافه شد: build_global_word2vec_model
# دقیقاً همان الگوی build_global_fasttext_model، اما برای شاخه BiLSTM.
# یکبار اجرا می‌شود (یا لود می‌شود اگر قبلاً ساخته شده).
# روی نمونه‌ای از کل corpus آموزش می‌بیند تا vocabulary مشترک ایجاد کند
# و شاخه BiLSTM هم مثل شاخه U-Net از یک فضای برداری یکپارچه استفاده کند.
# =============================================================================
def build_global_word2vec_model(max_contracts=15000):
    """
    آموزش یک مدل Word2Vec سراسری روی نمونه‌ای از کل corpus.

    دلیل:
    درست مثل build_global_fasttext_model: وقتی به ازای هر function یک
    Word2Vec جداگانه می‌سازیم، بردار یک توکن مشابه در دو function متفاوت،
    بردارهای کاملاً متفاوتی می‌گیرد چون context هر function محدود است.
    با یک مدل سراسری، تمام توابع در یک فضای برداری یکپارچه قرار می‌گیرند
    و شبکه (BiLSTM) می‌تواند روابط معنایی پایدار را یاد بگیرد.
    """
    all_tokens_global = []
    files = [os.path.join(PATH, f) for f in os.listdir(PATH) if f.endswith(".sol")]

    # محدود کردن برای سرعت - حتی 15000 قرارداد کافی است برای پوشش vocabulary
    if len(files) > max_contracts:
        import random
        random.seed(42)
        files = random.sample(files, max_contracts)

    print(f"Building global Word2Vec corpus from {len(files)} contracts...")

    for file_idx, file in enumerate(files):
        if file_idx % 1000 == 0:
            print(f"  Processed {file_idx}/{len(files)} contracts...")
        try:
            with open(file, encoding="utf8") as f:
                contract_content = f.read()
        except Exception:
            continue

        functions = extract_functions_with_bodies(contract_content)
        for func in functions:
            fragments = PreProcessTools.get_fragments(func['function_body'])
            func_tokens = []
            for fragment in fragments:
                if fragment.strip():
                    tokens = tokenize_solidity_code(fragment)
                    if tokens:
                        func_tokens.extend(tokens)
            if func_tokens:
                all_tokens_global.append(func_tokens)

    print(f"Training global Word2Vec on {len(all_tokens_global)} functions...")
    global_model = Word2Vec(
        sentences=all_tokens_global,
        vector_size=vector_length,
        window=5,
        min_count=1,
        workers=4
    )
    global_model.save(GLOBAL_WORD2VEC_PATH)
    print(f"Global Word2Vec saved to {GLOBAL_WORD2VEC_PATH}")
    print(f"Vocabulary size: {len(global_model.wv)}")
    return global_model


# =============================================================================
# اضافه شد: vectorize_tokens_fasttext
# طبق درخواست شما: این تابع فقط برای آماده‌سازی داده‌ی ورودی attention map
# شاخه‌ی U-Net استفاده می‌شود. تابع vectorize_tokens (Word2Vec) که شاخه‌ی
# LSTM از آن استفاده می‌کند، هیچ تغییری نکرده و دست‌نخورده باقی مانده است.
#
# پیکربندی FastText بر اساس مقاله پایه (بخش ۳.۲): اندازه‌ی بردار (Embedding
# Size) برابر با ۳۰۰ (مطابق جدول ۲ مقاله)، و حالت CBOW (sg=0) - همان‌طور که
# مقاله می‌گوید Word2Vec و FastText هر دو در این پروژه بر پایه‌ی CBOW عمل
# می‌کنند. سایر پارامترها (window، min_count) در مقاله برای FastText به‌طور
# جداگانه مشخص نشده‌اند، پس دقیقاً همان مقادیر تابع vectorize_tokens
# (window=5, min_count=1) برای سازگاری حفظ شده‌اند.
# =============================================================================
def vectorize_tokens_fasttext(tokens, global_model=None):
    """
    تبدیل یک لیست از توکن‌ها به آرایه‌ای از بردارهای FastText.
    فقط برای آماده‌سازی ورودی attention map شاخه‌ی U-Net استفاده می‌شود.
    ورودی: همه توکن‌های یک function (نه یک fragment)
    خروجی: آرایه دو‌بعدی (sequence_length × vector_length)

    اصلاح شده: اولویت با مدل سراسری (global) اگر موجود باشد.
    دلیل: مدل سراسری فضای برداری یکپارچه‌تری دارد. در صورت عدم وجود،
    به حالت قبلی (محلی per-function) fallback می‌کند تا سازگاری
    با کد قبلی حفظ شود.
    """
    if global_model is not None:
        # استفاده از مدل سراسری که از بیرون پاس داده شده
        embeddings = [
            global_model.wv[word] if word in global_model.wv else np.zeros(vector_length)
            for word in tokens
        ]
    elif os.path.exists(GLOBAL_FASTTEXT_PATH):
        # لود مدل سراسری اگر قبلاً ساخته شده (fallback خودکار)
        loaded_model = FastText.load(GLOBAL_FASTTEXT_PATH)
        embeddings = [
            loaded_model.wv[word] if word in loaded_model.wv else np.zeros(vector_length)
            for word in tokens
        ]
    else:
        # Fallback به حالت قبلی (محلی per-function) - همان رفتار قبل
        fasttext_model = FastText(
            sentences=[tokens], vector_size=vector_length, window=5,
            min_count=1, workers=4, sg=0, bucket=2000
        )
        embeddings = [
            fasttext_model.wv[word] if word in fasttext_model.wv else np.zeros(vector_length)
            for word in tokens
        ]

    # اعمال padding یا truncate به sequence_length=100 - همانند قبل
    embeddings = embeddings[:sequence_length] + [np.zeros(vector_length)] * max(0, sequence_length - len(embeddings))
    return np.array(embeddings, dtype='float32')


# =============================================================================
# اضافه شد: create_attention_map
# این تابع جدید است و بخشی از مقاله پایه نیست - پیاده‌سازی روش
# Attention Map که قبلاً با هم بحث کردیم (ترکیب similarity matrix
# و co-occurrence matrix).
#
# ورودی: embedding_matrix با شکل (sequence_length, vector_length)
#         real_token_count = تعداد توکن‌های واقعی قبل از padding
# خروجی: ماتریس (sequence_length, sequence_length, 3) برای U-Net
#
# اصلاح ۱۳: کدگذاری سه‌کاناله به‌جای فشرده‌کردن در یک کانال
# مشکل نسخه‌ی قبلی: attention_map = similarity_matrix * co_matrix باعث
# می‌شد عدد ۰ دو معنای متفاوت داشته باشد - هم «کنار هم نبودند» و هم
# «کنار هم بودند ولی شباهتشان صفر یا منفی بود». چون similarity از cosine
# می‌آید بازه‌اش [-1, +1] است (-1 یعنی دو بردار کاملاً خلاف جهت/متضاد)،
# و هر نگاشت تک‌کاناله‌ای (مثل (sim+1)/2 قبل از ضرب) همچنان حداقل یک
# جفت حالت متفاوت را به همان عدد خروجی می‌رساند.
# راه‌حل: سه کانال مستقل (شبیه تصویر RGB) که شبکه خودش یاد می‌گیرد
# ترکیبشان کند:
#   کانال ۱ (co-occurrence خام): آیا دو توکن در فاصله window از هم
#      هستند؟ همیشه ۰ یا ۱ - بدون ابهام.
#   کانال ۲ (similarity خام): شباهت cosine نگاشته‌شده به [0,1]، حتی
#      برای توکن‌های دور از هم هم معنادار نگه داشته می‌شود (قبلاً این
#      اطلاعات برای توکن‌های دور از هم کاملاً دور ریخته می‌شد).
#   کانال ۳ (تعامل): حاصل‌ضرب دو کانال بالا - همان attention map قبلی،
#      اما به‌عنوان اطلاعات مکمل نه جایگزین.
# =============================================================================
def create_attention_map(embedding_matrix, real_token_count, window=co_occurrence_window):
    """
    :param embedding_matrix: آرایه (sequence_length, vector_length) - خروجی vectorize_tokens
    :param real_token_count: تعداد توکن‌های واقعی قبل از padding
    :param window: اندازه پنجره co-occurrence
    :return: آرایه (sequence_length, sequence_length, 3)
    """
    # مرحله ۱: similarity matrix با cosine similarity - بازه [-1, +1]
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

    # مرحله ۳: ساخت سه کانال مستقل
    channel_cooccurrence = co_matrix  # کانال ۱: همیشه ۰ یا ۱ - بدون ابهام
    channel_similarity = (similarity_matrix + 1) / 2  # کانال ۲: نگاشت [-1,1] به [0,1]
    channel_interaction = channel_similarity * co_matrix  # کانال ۳: تعامل دو کانال بالا

    attention_map = np.stack(
        [channel_cooccurrence, channel_similarity, channel_interaction], axis=-1
    )  # شکل خروجی: (seq_len, seq_len, 3)

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
                    padded_function = \
                    pad_sequences([func_vectors], maxlen=max_function_length, padding='post', dtype='float32')[0]

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
def process_batch_with_categorization_for_unet(files, target_vulnerability, batch_size, batch_index,
                                               global_fasttext_model=None, global_word2vec_model=None):
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
                    # =============================================================
                    # اصلاح: embedding برای شاخه BiLSTM - اکنون از بردارهای
                    # Word2Vec سراسری (اگر موجود باشد) استفاده می‌شود، دقیقاً
                    # مثل شاخه U-Net. global_word2vec_model از بیرون پاس داده
                    # می‌شود تا در هر batch مجبور به لود مجدد نباشیم.
                    # =============================================================
                    func_vectors = vectorize_tokens(all_tokens, global_model=global_word2vec_model)
                    padded_function = pad_sequences(
                        [func_vectors], maxlen=max_function_length, padding='post', dtype='float32'
                    )[0]

                    # =============================================================
                    # اصلاح: آماده‌سازی داده‌ی attention map شاخه‌ی U-Net
                    # اکنون از بردارهای FastText سراسری (اگر موجود باشد) استفاده می‌شود.
                    # global_fasttext_model از بیرون پاس داده می‌شود تا در هر batch
                    # مجبور به لود مجدد نباشیم.
                    # =============================================================
                    func_vectors_fasttext = vectorize_tokens_fasttext(
                        all_tokens, global_model=global_fasttext_model
                    )
                    padded_function_fasttext = pad_sequences(
                        [func_vectors_fasttext], maxlen=max_function_length, padding='post', dtype='float32'
                    )[0]

                    # attention map برای شاخه U-Net
                    real_token_count = min(len(all_tokens), sequence_length)
                    att_map = create_attention_map(padded_function_fasttext, real_token_count)

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

    # =============================================================================
    # اصلاح ۹ (بازبینی‌شده): BatchNormalization به‌طور کامل حذف شد
    # دلیل: در آزمایش واقعی روی این attention map (که خیلی sparse است)،
    # BatchNormalization باعث ناسازگاری آمار train/inference و collapse شدن
    # مدل روی یک کلاس در validation شد (دقت از 86.73% به 64.32% سقوط کرد).
    # به‌عنوان تصمیم مهندسی، به‌جای ریسک دوباره BatchNorm (حتی با احتیاط)،
    # فقط از Dropout برای کنترل overfitting استفاده می‌شود که در آزمایش قبلی
    # هیچ بی‌ثباتی ایجاد نکرد.
    # =============================================================================
    # Encoder
    conv1 = Conv2D(64, (3, 3), activation='relu', padding='same')(inputs)
    pool1 = MaxPooling2D((2, 2))(conv1)

    conv2 = Conv2D(128, (3, 3), activation='relu', padding='same')(pool1)
    pool2 = MaxPooling2D((2, 2))(conv2)

    # Bottleneck
    conv3 = Conv2D(256, (3, 3), activation='relu', padding='same')(pool2)
    # =============================================================================
    # اصلاح ۱۵: Dropout معمولی → SpatialDropout2D
    # دلیل: Dropout معمولی روی یک feature map کانولوشنی هر پیکسل را
    # مستقل صفر می‌کند، اما پیکسل‌های همسایه در feature map به‌شدت
    # همبسته‌اند (از یک kernel مشترک آمده‌اند)، پس شبکه به‌راحتی می‌تواند
    # مقدار حذف‌شده را از همسایه‌ها «حدس بزند» و اثر regularization ضعیف
    # می‌شود. SpatialDropout2D کل یک کانال feature map را حذف می‌کند که
    # برای این نوع لایه استاندارد و مؤثرتر است.
    # =============================================================================
    conv3 = SpatialDropout2D(0.3)(conv3)

    # Decoder
    up1 = UpSampling2D((2, 2))(conv3)
    concat1 = concatenate([conv2, up1])
    conv4 = Conv2D(128, (3, 3), activation='relu', padding='same')(concat1)

    up2 = UpSampling2D((2, 2))(conv4)
    concat2 = concatenate([conv1, up2])
    conv5 = Conv2D(64, (3, 3), activation='relu', padding='same')(concat2)

    # =============================================================================
    # اصلاح ۱۲: GlobalMaxPooling2D کنار GlobalAveragePooling2D
    # دلیل: توابع کوتاه‌تر از sequence_length، بخش بزرگی از نقشه‌شان صفر
    # (padding) است. GlobalAveragePooling2D به‌تنهایی این صفرها را هم در
    # میانگین حساب می‌کند و سیگنال واقعی را رقیق می‌کند. GlobalMaxPooling2D
    # کمتر تحت‌تأثیر padding قرار می‌گیرد و الگوهای قوی موضعی را حفظ می‌کند؛
    # هر دو با هم concatenate می‌شوند تا هیچ اطلاعاتی از دست نرود.
    # =============================================================================
    avg_pool = GlobalAveragePooling2D()(conv5)
    max_pool = GlobalMaxPooling2D()(conv5)
    pooled = concatenate([avg_pool, max_pool])

    dense_out = Dense(128, activation='relu')(pooled)
    # =============================================================================
    # اصلاح ۱۶: Dropout اضافی بعد از pooling حذف شد
    # دلیل: مجموع Dropout(bottleneck) + Dropout(اینجا) + Dropout(head در
    # build_unet_only_model) + L2 روی مدلی با کمتر از ۱ میلیون پارامتر،
    # برای یک overfitting نسبتاً خفیف (val_loss فقط 0.0206→0.0260) زیاده‌روی
    # است و ریسک واقعی underfitting دارد. این لایه حذف شد؛ فقط SpatialDropout2D
    # در bottleneck و Dropout+L2 در build_unet_only_model باقی می‌ماند.
    # =============================================================================

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
    # اصلاح ۱۳ (ادامه): شکل ورودی از 1 کانال به 3 کانال تغییر کرد چون
    # create_attention_map حالا (seq_len, seq_len, 3) برمی‌گرداند.
    unet_input, unet_output = build_unet_branch((seq_len, seq_len, 3))
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

    os.makedirs(os.path.join(ROOT, 'output'), exist_ok=True)
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

    # =============================================================================
    # اصلاح: قبلاً از مسیر نسبی استفاده می‌شد که باعث می‌شد نمودار در
    # دایرکتوری کاری فعلی (contracts/) ذخیره شود، نه در پوشه output.
    # حالا مثل train_LSTM و test_unet_branch_alone در ROOT/output ذخیره می‌شود.
    # =============================================================================
    os.makedirs(os.path.join(ROOT, 'output'), exist_ok=True)
    output_image_path = os.path.join(ROOT, 'output', 'training_plot_unet_attention_lstm.png')
    plt.savefig(output_image_path, dpi=300, bbox_inches='tight')
    print(f"Plot saved to {output_image_path}")
    plt.show()

    Y_pred = (model.predict([X_att_test, X_emb_test]) > 0.5).astype("int32")

    accuracy = accuracy_score(Y_test, Y_pred)
    report = classification_report(Y_test, Y_pred, target_names=['Safe', 'Vulnerable'], labels=[0, 1])

    print(f"Accuracy: {accuracy}")
    print("Classification Report:")
    print(report)

    model.save(os.path.join(ROOT, 'output', 'final_unet_attention_lstm_model.keras'))
    print("Training complete with U-Net(AttentionMap) + BiLSTM.")


def train_LSTM():
    # =============================================================================
    # اصلاح جدید: چون الان همه دیتاست در vectorcollections_img ریخته شده،
    # به‌جای خواندن از CACHE_DIR (vectorcollections)، از CACHE_DIR_UNET
    # با پیشوند emb_ خوانده می‌شود - یعنی همان فایل‌های embedding که برای
    # شاخه BiLSTM ساخته شده بودند، اینجا هم برای LSTM تنها استفاده می‌شوند.
    # تابع load_batches اصلی (که از CACHE_DIR می‌خواند) دست‌نخورده باقی
    # مانده، فقط اینجا فراخوانی آن با load_batches_by_prefix جایگزین شد.
    # =============================================================================
    X, Y = load_batches_by_prefix(CACHE_DIR_UNET, prefix="emb_")
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
        batch_size=128,  # اصلاح شد: از 32 به 128 مطابق مقاله
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
    model.save(os.path.join(ROOT, 'output', 'final_LSTM_model.keras'))

    print("Training complete with LSTM.")


# =============================================================================
# اضافه شد: build_unet_only_model
# مدل جداگانه که فقط شاخه U-Net را دارد (بدون BiLSTM) - برای تست مستقل
# اینکه آیا attention_map به‌تنهایی سیگنال مفیدی دارد یا نه.
# از همان build_unet_branch موجود استفاده می‌کند - هیچ تابع دیگری
# تغییر نکرده است.
# =============================================================================
def build_unet_only_model(seq_len=sequence_length):
    # اصلاح ۱۳ (ادامه): شکل ورودی از 1 کانال به 3 کانال تغییر کرد چون
    # create_attention_map حالا (seq_len, seq_len, 3) برمی‌گرداند.
    unet_input, unet_output = build_unet_branch((seq_len, seq_len, 3))
    # =============================================================================
    # اصلاح ۱۴ (بازبینی‌شده): Dropout و L2 regularization روی سر (head) طبقه‌بندی
    # علاوه بر SpatialDropout2D داخل build_unet_branch، یک Dropout و
    # kernel_regularizer='l2' هم اینجا اضافه شده. طبق اصلاح ۱۶، لایه‌ی
    # Dropout دوم بعد از dense1 حذف شد تا مجموع regularization متناسب با
    # شدت overfitting اصلی (نسبتاً خفیف) بماند و ریسک underfitting کم شود.
    # =============================================================================
    x = Dropout(0.3)(unet_output)
    dense1 = Dense(64, activation='relu', kernel_regularizer='l2')(x)
    outputs = Dense(1, activation='sigmoid')(dense1)
    model = Model(inputs=unet_input, outputs=outputs)
    return model


# =============================================================================
# اضافه شد: test_unet_branch_alone
# تست مستقل شاخه U-Net (بدون BiLSTM) روی داده attention_map.
# فقط از فایل‌های att_ در CACHE_DIR_UNET استفاده می‌کند.
# مدل نهایی را در پوشه output ذخیره می‌کند تا در check_ensemble_potential
# قابل استفاده باشد.
# =============================================================================
def test_unet_branch_alone():
    # فقط attention map بارگذاری می‌شود - embedding لازم نیست
    X_att, Y_att = load_batches_by_prefix(CACHE_DIR_UNET, prefix="att_")
    print(f"Shape of X_att: {X_att.shape}")
    print("Distribution in Y:", np.unique(Y_att, return_counts=True))

    X_train, X_test, Y_train, Y_test = train_test_split(
        X_att, Y_att, test_size=0.2, random_state=42
    )

    # نسبت کلاس اکثریت در Y_test - این کف مقایسه (baseline) است
    majority_baseline = max(np.mean(Y_test == 0), np.mean(Y_test == 1))
    print(f"Majority-class baseline accuracy: {majority_baseline:.4f}")

    model = build_unet_only_model()

    model.compile(
        optimizer=Adam(learning_rate=0.001),
        loss=focal_loss(alpha=0.25, gamma=2.0),
        metrics=['accuracy']
    )

    model.summary()

    early_stopping = EarlyStopping(
        monitor='val_accuracy',
        mode='max',
        patience=10,
        restore_best_weights=True
    )

    # =============================================================================
    # اصلاح ۱۱: اضافه شدن ReduceLROnPlateau و ModelCheckpoint
    # طبق درخواست شما (مرحله ۲ از پیشنهادهای بهبود U-Net): وقتی val_loss
    # گیر می‌کند (مثل چیزی که در آموزش قبلی از epoch ~13 به بعد دیده شد)،
    # نرخ یادگیری به‌طور خودکار کم می‌شود. همچنین بهترین وزن‌ها علاوه بر
    # restore_best_weights در حافظه، روی دیسک هم ذخیره می‌شوند.
    # =============================================================================
    reduce_lr = ReduceLROnPlateau(
        monitor='val_accuracy',
        mode='max',
        factor=0.5,
        patience=4,
        min_lr=1e-6,
        verbose=1
    )

    os.makedirs(os.path.join(ROOT, 'output'), exist_ok=True)
    checkpoint = ModelCheckpoint(
        os.path.join(ROOT, 'output', 'best_unet_only_model.keras'),
        monitor='val_accuracy',
        mode='max',
        save_best_only=True
    )

    history = model.fit(
        X_train, Y_train,
        epochs=50,
        batch_size=128,
        validation_split=0.2,
        callbacks=[early_stopping, reduce_lr, checkpoint],  # اصلاح ۱۱: callback های جدید اضافه شد
        verbose=2
    )

    os.makedirs(os.path.join(ROOT, 'output'), exist_ok=True)
    plt.figure(figsize=(10, 6))
    plt.plot(history.history['accuracy'], label='train acc', color='blue')
    plt.plot(history.history['val_accuracy'], label='val acc', color='yellow')
    plt.plot(history.history['loss'], label='train loss', color='red')
    plt.plot(history.history['val_loss'], label='val loss', color='green')
    plt.title('U-Net Only (Attention Map) - Accuracy and Loss')
    plt.xlabel('Epochs')
    plt.ylabel('Accuracy / Loss')
    plt.legend(loc='best')
    plt.grid()
    output_image_path = os.path.join(ROOT, 'output', 'training_plot_unet_only.png')
    plt.savefig(output_image_path, dpi=300, bbox_inches='tight')
    print(f"Plot saved to {output_image_path}")
    plt.show()

    Y_pred = (model.predict(X_test) > 0.5).astype("int32")
    accuracy = accuracy_score(Y_test, Y_pred)

    print(f"\n{'=' * 50}")
    print(f"U-Net-only accuracy:       {accuracy:.4f}")
    print(f"Majority-class baseline:   {majority_baseline:.4f}")
    print(f"Improvement over baseline: {(accuracy - majority_baseline) * 100:.2f}%")
    print(f"{'=' * 50}\n")

    print("Classification Report:")
    print(classification_report(Y_test, Y_pred, target_names=['Safe', 'Vulnerable'], labels=[0, 1]))

    # اضافه شد: ذخیره مدل برای استفاده در check_ensemble_potential
    model.save(os.path.join(ROOT, 'output', 'final_unet_only_model.keras'))
    print(f"Model saved to {os.path.join(ROOT, 'output', 'final_unet_only_model.keras')}")


# =============================================================================
# اضافه شد: check_ensemble_potential
# این تابع بررسی می‌کند آیا مدل LSTM (final_LSTM_model.h5) و مدل
# U-Net تنها (final_unet_only_model.h5) روی نمونه‌های متفاوتی اشتباه
# می‌کنند یا نه - قبل از سرمایه‌گذاری روی ساخت یک ensemble کامل.
# نیازمند این است که هم train_LSTM() و هم test_unet_branch_alone()
# قبلاً اجرا و مدل‌هایشان در پوشه output ذخیره شده باشند.
# =============================================================================
def check_ensemble_potential():

    X_att, Y_att = load_batches_by_prefix(CACHE_DIR_UNET, prefix="att_")
    X_emb, Y_emb = load_batches_by_prefix(CACHE_DIR_UNET, prefix="emb_")

    assert np.array_equal(Y_att, Y_emb), "ترتیب Y بین att و emb یکسان نیست - فایل‌ها را بررسی کنید"

    indices = np.arange(len(Y_att))
    train_idx, test_idx = train_test_split(indices, test_size=0.2, random_state=42)
    X_att_test, X_emb_test = X_att[test_idx], X_emb[test_idx]
    Y_test = Y_att[test_idx]

    lstm_model = load_model(
        os.path.join(ROOT, 'output', 'final_LSTM_model.keras'),
        custom_objects={'loss': focal_loss(alpha=0.25, gamma=2.0)}
    )
    unet_model = load_model(
        os.path.join(ROOT, 'output', 'final_unet_only_model.keras'),
        custom_objects={'loss': focal_loss(alpha=0.25, gamma=2.0)}
    )

    p_lstm = lstm_model.predict(X_emb_test).flatten()
    p_unet = unet_model.predict(X_att_test).flatten()

    pred_lstm = (p_lstm > 0.5).astype(int)
    pred_unet = (p_unet > 0.5).astype(int)

    lstm_correct = (pred_lstm == Y_test)
    unet_correct = (pred_unet == Y_test)

    only_lstm_right = np.mean(lstm_correct & ~unet_correct)
    only_unet_right = np.mean(~lstm_correct & unet_correct)
    both_right = np.mean(lstm_correct & unet_correct)
    both_wrong = np.mean(~lstm_correct & ~unet_correct)

    print(f"فقط LSTM درست:  {only_lstm_right*100:.2f}%")
    print(f"فقط U-Net درست: {only_unet_right*100:.2f}%")
    print(f"هر دو درست:     {both_right*100:.2f}%")
    print(f"هر دو غلط:      {both_wrong*100:.2f}%")
    print(f"\nپتانسیل بهبود از ensemble: {(only_lstm_right + only_unet_right)*100:.2f}%")


# =============================================================================
# اضافه شد: build_stacking_meta_model
# یک مدل بسیار ساده که فقط دو عدد ورودی می‌گیرد: احتمال خروجی مدل LSTM
# و احتمال خروجی مدل U-Net. یاد می‌گیرد چطور این دو عدد را برای رسیدن
# به تصمیم نهایی ترکیب کند. این با concatenate کردن feature های خام
# (که در build_unet_bilstm_model امتحان شد) کاملاً متفاوت است، چون
# اینجا دو مدل جداگانه کامل train شده‌اند و فقط خروجی نهایی‌شان
# ترکیب می‌شود - نه اینکه از اول با هم train شوند.
# =============================================================================
def build_stacking_meta_model():
    meta_input = Input(shape=(2,), name='meta_input')
    x = Dense(8, activation='relu')(meta_input)
    output = Dense(1, activation='sigmoid')(x)
    model = Model(inputs=meta_input, outputs=output)
    return model


# =============================================================================
# اضافه شد: train_stacking_ensemble
# نیازمند این است که final_LSTM_model.h5 و final_unet_only_model.h5
# قبلاً train و در پوشه output ذخیره شده باشند (یعنی train_LSTM() و
# test_unet_branch_alone() قبلاً اجرا شده باشند).
# =============================================================================
def train_stacking_ensemble():

    X_att, Y_att = load_batches_by_prefix(CACHE_DIR_UNET, prefix="att_")
    X_emb, Y_emb = load_batches_by_prefix(CACHE_DIR_UNET, prefix="emb_")
    assert np.array_equal(Y_att, Y_emb), "ترتیب Y بین att و emb یکسان نیست - فایل‌ها را بررسی کنید"

    indices = np.arange(len(Y_att))
    train_idx, test_idx = train_test_split(indices, test_size=0.2, random_state=42)

    X_att_train, X_att_test = X_att[train_idx], X_att[test_idx]
    X_emb_train, X_emb_test = X_emb[train_idx], X_emb[test_idx]
    Y_train, Y_test = Y_att[train_idx], Y_att[test_idx]

    lstm_model = load_model(
        os.path.join(ROOT, 'output', 'final_LSTM_model.keras'),
        custom_objects={'loss': focal_loss(alpha=0.25, gamma=2.0)}
    )
    unet_model = load_model(
        os.path.join(ROOT, 'output', 'final_unet_only_model.keras'),
        custom_objects={'loss': focal_loss(alpha=0.25, gamma=2.0)}
    )

    # ساخت feature های meta-model: خروجی احتمال هر دو مدل پایه
    print("در حال پیش‌بینی با مدل‌های پایه روی داده train...")
    p_lstm_train = lstm_model.predict(X_emb_train).flatten()
    p_unet_train = unet_model.predict(X_att_train).flatten()
    meta_X_train = np.column_stack([p_lstm_train, p_unet_train])

    print("در حال پیش‌بینی با مدل‌های پایه روی داده test...")
    p_lstm_test = lstm_model.predict(X_emb_test).flatten()
    p_unet_test = unet_model.predict(X_att_test).flatten()
    meta_X_test = np.column_stack([p_lstm_test, p_unet_test])

    meta_model = build_stacking_meta_model()
    meta_model.compile(
        optimizer=Adam(learning_rate=0.001),
        loss=focal_loss(alpha=0.25, gamma=2.0),
        metrics=['accuracy']
    )

    early_stopping = EarlyStopping(monitor='val_loss', patience=10, restore_best_weights=True)

    meta_model.fit(
        meta_X_train, Y_train,
        epochs=50,
        batch_size=128,
        validation_split=0.2,
        callbacks=[early_stopping],
        verbose=2
    )

    Y_pred = (meta_model.predict(meta_X_test) > 0.5).astype("int32")
    accuracy = accuracy_score(Y_test, Y_pred)

    print(f"\n{'='*50}")
    print(f"Stacking Ensemble Accuracy: {accuracy:.4f}")
    print(f"{'='*50}\n")
    print("Classification Report:")
    print(classification_report(Y_test, Y_pred, target_names=['Safe', 'Vulnerable'], labels=[0, 1]))

    os.makedirs(os.path.join(ROOT, 'output'), exist_ok=True)
    meta_model.save(os.path.join(ROOT, 'output', 'final_stacking_ensemble.keras'))
    print(f"Model saved to {os.path.join(ROOT, 'output', 'final_stacking_ensemble.keras')}")

if __name__ == "__main__":
    # files = [os.path.join(PATH, f) for f in os.listdir(PATH) if f.endswith(".sol")]
    # print(f"size files {files.__len__()}")

    # =============================================================================
    # اضافه شد: ساخت/لود یک‌بارهٔ مدل FastText سراسری قبل از شروع batch‌ها
    # تا embedding شاخهٔ U-Net (attention map) در همهٔ نمونه‌ها یکسان و
    # قابل generalize باشد، نه per-function جداگانه.
    # =============================================================================
    # if os.path.exists(GLOBAL_FASTTEXT_PATH):
    #     global_ft_model = FastText.load(GLOBAL_FASTTEXT_PATH)
    # else:
    #     global_ft_model = build_global_fasttext_model()

    # =============================================================================
    # اضافه شد: ساخت/لود یک‌بارهٔ مدل Word2Vec سراسری قبل از شروع batch‌ها
    # دقیقاً مثل global_ft_model بالا، اما برای شاخه BiLSTM - تا embedding
    # شاخهٔ BiLSTM هم در همهٔ نمونه‌ها یکسان و قابل generalize باشد، نه
    # per-function جداگانه.
    # =============================================================================
    # if os.path.exists(GLOBAL_WORD2VEC_PATH):
    #     global_w2v_model = Word2Vec.load(GLOBAL_WORD2VEC_PATH)
    # else:
    #     global_w2v_model = build_global_word2vec_model()

    # =============================================================================
    # تغییر: طبق درخواست شما، در همین اجرای اول، دیتاست هر دو حالت
    # (LSTM تنها و U-Net+BiLSTM) در یک حلقه ساخته می‌شوند:
    #   - process_batch_with_categorization      → ذخیره در vectorcollections/
    #   - process_batch_with_categorization_for_unet → ذخیره در vectorcollections_img/
    # این دو تابع کاملاً مستقل از هم هستند و در دو مسیر جدا ذخیره می‌کنند،
    # پس هیچ تداخلی با هم ندارند.
    # =============================================================================
    # for batch_index, i in enumerate(range(0, len(files), batch_size)):
    #     if batch_index > 40:
    #         batch_files = files[i:i + batch_size]
    #         print(f"size batch_files {batch_files.__len__()}")
    #         process_batch_with_categorization_for_unet(
    #             batch_files, target_vulner, batch_size, batch_index,
    #             global_fasttext_model=global_ft_model,
    #             global_word2vec_model=global_w2v_model
    #         )
# if __name__ == "__main__":
#     files = [os.path.join(PATH, f) for f in os.listdir(PATH) if f.endswith(".sol")]
#     print(f"size files {files.__len__()}")
#
#     # =============================================================================
#     # تغییر: طبق درخواست شما، در همین اجرای اول، دیتاست هر دو حالت
#     # (LSTM تنها و U-Net+BiLSTM) در یک حلقه ساخته می‌شوند:
#     #   - process_batch_with_categorization      → ذخیره در vectorcollections/
#     #   - process_batch_with_categorization_for_unet → ذخیره در vectorcollections_img/
#     # این دو تابع کاملاً مستقل از هم هستند و در دو مسیر جدا ذخیره می‌کنند،
#     # پس هیچ تداخلی با هم ندارند.
#     # =============================================================================
#     for batch_index, i in enumerate(range(0, len(files), batch_size)):
#         # if batch_index > 29:
#             # continue
#             batch_files = files[i:i + batch_size]
#             print(f"size batch_files {batch_files.__len__()}")
#             process_batch_with_categorization_for_unet(batch_files, target_vulner, batch_size, batch_index)

    # =============================================================================
    # بخش آموزش: طبق درخواست شما این‌ها به‌صورت جدا و در اجراهای متفاوت
    # فراخوانی می‌شوند - نه همزمان. هر بار فقط یکی را از کامنت خارج کنید:
    #
    #   ۱. train_LSTM()               → آموزش و ذخیره مدل LSTM تنها
    #   ۲. train_UNET_LSTM()          → آموزش مدل ترکیبی U-Net+BiLSTM (joint)
    #   ۳. test_unet_branch_alone()   → آموزش و ذخیره مدل U-Net تنها
    #   ۴. check_ensemble_potential() → بررسی پتانسیل ensemble
    #      (نیازمند اجرای قبلی شماره ۱ و ۳ برای وجود فایل‌های مدل ذخیره‌شده)
    #   ۵. train_stacking_ensemble()  → آموزش meta-model روی خروجی هر دو مدل
    #      (نیازمند اجرای قبلی شماره ۱ و ۳ برای وجود فایل‌های مدل ذخیره‌شده)
    # =============================================================================
    # train_LSTM()
    train_UNET_LSTM()
    # test_unet_branch_alone()
    # check_ensemble_potential()
    # train_stacking_ensemble()

# 2026-09-06 18:09:54.926426: I tensorflow/core/platform/cpu_feature_guard.cc:210] This TensorFlow binary is optimized to use available CPU instructions in performance-critical operations.
# To enable the following instructions: AVX2 AVX512F FMA, in other operations, rebuild TensorFlow with the appropriate compiler flags.
# Shape of X: (47619, 100, 300)
# Shape of Y: (47619,)
# Distribution in Y: (array([0, 1], dtype=int32), array([28520, 19099]))
# Distribution in Y_test: (array([0, 1], dtype=int32), array([5683, 3841]))
# 2026-09-06 18:10:24.137908: W tensorflow/core/common_runtime/gpu/gpu_bfc_allocator.cc:47] Overriding orig_value setting because the TF_FORCE_GPU_ALLOW_GROWTH environment variable is set. Original config value was 0.
# WARNING: All log messages before absl::InitializeLog() is called are written to STDERR
# I0000 00:00:1788718224.139385   13413 gpu_device.cc:2020] Created device /job:localhost/replica:0/task:0/device:GPU:0 with 13757 MB memory:  -> device: 0, name: Tesla T4, pci bus id: 0000:00:04.0, compute capability: 7.5
# 2026-09-06 18:10:30.127205: W external/local_xla/xla/tsl/framework/cpu_allocator_impl.cc:84] Allocation of 3657120000 exceeds 10% of free system memory.
# 2026-09-06 18:10:33.797200: W external/local_xla/xla/tsl/framework/cpu_allocator_impl.cc:84] Allocation of 3657120000 exceeds 10% of free system memory.
# Epoch 1/50
# 2026-09-06 18:10:40.038711: I external/local_xla/xla/stream_executor/cuda/cuda_dnn.cc:473] Loaded cuDNN version 91900
# 2026-09-06 18:10:51.499592: W external/local_xla/xla/tsl/framework/cpu_allocator_impl.cc:84] Allocation of 914280000 exceeds 10% of free system memory.
# 2026-09-06 18:10:52.478280: W external/local_xla/xla/tsl/framework/cpu_allocator_impl.cc:84] Allocation of 914280000 exceeds 10% of free system memory.
# 239/239 - 18s - 77ms/step - accuracy: 0.8016 - loss: 0.0270 - val_accuracy: 0.8127 - val_loss: 0.0250
# Epoch 2/50
# 239/239 - 9s - 40ms/step - accuracy: 0.8459 - loss: 0.0223 - val_accuracy: 0.8296 - val_loss: 0.0231
# Epoch 3/50
# 239/239 - 10s - 40ms/step - accuracy: 0.8539 - loss: 0.0210 - val_accuracy: 0.8449 - val_loss: 0.0221
# Epoch 4/50
# 239/239 - 10s - 40ms/step - accuracy: 0.8639 - loss: 0.0200 - val_accuracy: 0.8432 - val_loss: 0.0213
# Epoch 5/50
# 239/239 - 10s - 41ms/step - accuracy: 0.8718 - loss: 0.0190 - val_accuracy: 0.8580 - val_loss: 0.0208
# Epoch 6/50
# 239/239 - 10s - 41ms/step - accuracy: 0.8755 - loss: 0.0182 - val_accuracy: 0.8550 - val_loss: 0.0204
# Epoch 7/50
# 239/239 - 10s - 41ms/step - accuracy: 0.8839 - loss: 0.0174 - val_accuracy: 0.8665 - val_loss: 0.0196
# Epoch 8/50
# 239/239 - 10s - 42ms/step - accuracy: 0.8911 - loss: 0.0165 - val_accuracy: 0.8647 - val_loss: 0.0200
# Epoch 9/50
# 239/239 - 10s - 43ms/step - accuracy: 0.8945 - loss: 0.0159 - val_accuracy: 0.8693 - val_loss: 0.0193
# Epoch 10/50
# 239/239 - 10s - 42ms/step - accuracy: 0.9012 - loss: 0.0150 - val_accuracy: 0.8706 - val_loss: 0.0187
# Epoch 11/50
# 239/239 - 10s - 42ms/step - accuracy: 0.9049 - loss: 0.0146 - val_accuracy: 0.8761 - val_loss: 0.0196
# Epoch 12/50
# 239/239 - 10s - 42ms/step - accuracy: 0.9103 - loss: 0.0137 - val_accuracy: 0.8735 - val_loss: 0.0208
# Epoch 13/50
# 239/239 - 10s - 42ms/step - accuracy: 0.9167 - loss: 0.0130 - val_accuracy: 0.8760 - val_loss: 0.0210
# Epoch 14/50
# 239/239 - 10s - 42ms/step - accuracy: 0.9194 - loss: 0.0124 - val_accuracy: 0.8832 - val_loss: 0.0209
# Epoch 15/50
# 239/239 - 10s - 42ms/step - accuracy: 0.9249 - loss: 0.0117 - val_accuracy: 0.8824 - val_loss: 0.0234
# Epoch 16/50
# 239/239 - 10s - 42ms/step - accuracy: 0.9281 - loss: 0.0115 - val_accuracy: 0.8855 - val_loss: 0.0215
# Epoch 17/50
# 239/239 - 10s - 42ms/step - accuracy: 0.9302 - loss: 0.0110 - val_accuracy: 0.8862 - val_loss: 0.0210
# Epoch 18/50
# 239/239 - 10s - 42ms/step - accuracy: 0.9340 - loss: 0.0105 - val_accuracy: 0.8808 - val_loss: 0.0228
# Epoch 19/50
# 239/239 - 10s - 42ms/step - accuracy: 0.9359 - loss: 0.0103 - val_accuracy: 0.8821 - val_loss: 0.0234
# Epoch 20/50
# 239/239 - 10s - 42ms/step - accuracy: 0.9391 - loss: 0.0099 - val_accuracy: 0.8855 - val_loss: 0.0251
# Plot saved to /content/smartbugs-wild-with-content-and-result/output/training_plot_lstm.png
# Figure(1000x600)
# 2026-09-06 18:14:04.733277: W external/local_xla/xla/tsl/framework/cpu_allocator_impl.cc:84] Allocation of 1142880000 exceeds 10% of free system memory.
# 298/298 ━━━━━━━━━━━━━━━━━━━━ 3s 9ms/step
# Accuracy: 0.8732675346493071
# Classification Report:
#               precision    recall  f1-score   support
#
#         Safe       0.87      0.92      0.90      5683
#   Vulnerable       0.87      0.80      0.84      3841
#
#     accuracy                           0.87      9524
#    macro avg       0.87      0.86      0.87      9524
# weighted avg       0.87      0.87      0.87      9524
#
# Training complete with LSTM.
#
# ===================================================================

# 2026-09-06 18:53:27.690985: I tensorflow/core/platform/cpu_feature_guard.cc:210] This TensorFlow binary is optimized to use available CPU instructions in performance-critical operations.
# To enable the following instructions: AVX2 AVX512F FMA, in other operations, rebuild TensorFlow with the appropriate compiler flags.
# Shape of X_att: (47619, 100, 100, 3)
# Distribution in Y: (array([0, 1], dtype=int32), array([28520, 19099]))
# Majority-class baseline accuracy: 0.5967
# 2026-09-06 18:53:59.042799: W tensorflow/core/common_runtime/gpu/gpu_bfc_allocator.cc:47] Overriding orig_value setting because the TF_FORCE_GPU_ALLOW_GROWTH environment variable is set. Original config value was 0.
# WARNING: All log messages before absl::InitializeLog() is called are written to STDERR
# I0000 00:00:1788720839.044282   25601 gpu_device.cc:2020] Created device /job:localhost/replica:0/task:0/device:GPU:0 with 13757 MB memory:  -> device: 0, name: Tesla T4, pci bus id: 0000:00:04.0, compute capability: 7.5
# Model: "functional"
# ┏━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━┓
# ┃ Layer (type)        ┃ Output Shape      ┃    Param # ┃ Connected to      ┃
# ┡━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━┩
# │ attention_map_input │ (None, 100, 100,  │          0 │ -                 │
# │ (InputLayer)        │ 3)                │            │                   │
# ├─────────────────────┼───────────────────┼────────────┼───────────────────┤
# │ conv2d (Conv2D)     │ (None, 100, 100,  │      1,792 │ attention_map_in… │
# │                     │ 64)               │            │                   │
# ├─────────────────────┼───────────────────┼────────────┼───────────────────┤
# │ max_pooling2d       │ (None, 50, 50,    │          0 │ conv2d[0][0]      │
# │ (MaxPooling2D)      │ 64)               │            │                   │
# ├─────────────────────┼───────────────────┼────────────┼───────────────────┤
# │ conv2d_1 (Conv2D)   │ (None, 50, 50,    │     73,856 │ max_pooling2d[0]… │
# │                     │ 128)              │            │                   │
# ├─────────────────────┼───────────────────┼────────────┼───────────────────┤
# │ max_pooling2d_1     │ (None, 25, 25,    │          0 │ conv2d_1[0][0]    │
# │ (MaxPooling2D)      │ 128)              │            │                   │
# ├─────────────────────┼───────────────────┼────────────┼───────────────────┤
# │ conv2d_2 (Conv2D)   │ (None, 25, 25,    │    295,168 │ max_pooling2d_1[… │
# │                     │ 256)              │            │                   │
# ├─────────────────────┼───────────────────┼────────────┼───────────────────┤
# │ spatial_dropout2d   │ (None, 25, 25,    │          0 │ conv2d_2[0][0]    │
# │ (SpatialDropout2D)  │ 256)              │            │                   │
# ├─────────────────────┼───────────────────┼────────────┼───────────────────┤
# │ up_sampling2d       │ (None, 50, 50,    │          0 │ spatial_dropout2… │
# │ (UpSampling2D)      │ 256)              │            │                   │
# ├─────────────────────┼───────────────────┼────────────┼───────────────────┤
# │ concatenate         │ (None, 50, 50,    │          0 │ conv2d_1[0][0],   │
# │ (Concatenate)       │ 384)              │            │ up_sampling2d[0]… │
# ├─────────────────────┼───────────────────┼────────────┼───────────────────┤
# │ conv2d_3 (Conv2D)   │ (None, 50, 50,    │    442,496 │ concatenate[0][0] │
# │                     │ 128)              │            │                   │
# ├─────────────────────┼───────────────────┼────────────┼───────────────────┤
# │ up_sampling2d_1     │ (None, 100, 100,  │          0 │ conv2d_3[0][0]    │
# │ (UpSampling2D)      │ 128)              │            │                   │
# ├─────────────────────┼───────────────────┼────────────┼───────────────────┤
# │ concatenate_1       │ (None, 100, 100,  │          0 │ conv2d[0][0],     │
# │ (Concatenate)       │ 192)              │            │ up_sampling2d_1[… │
# ├─────────────────────┼───────────────────┼────────────┼───────────────────┤
# │ conv2d_4 (Conv2D)   │ (None, 100, 100,  │    110,656 │ concatenate_1[0]… │
# │                     │ 64)               │            │                   │
# ├─────────────────────┼───────────────────┼────────────┼───────────────────┤
# │ global_average_poo… │ (None, 64)        │          0 │ conv2d_4[0][0]    │
# │ (GlobalAveragePool… │                   │            │                   │
# ├─────────────────────┼───────────────────┼────────────┼───────────────────┤
# │ global_max_pooling… │ (None, 64)        │          0 │ conv2d_4[0][0]    │
# │ (GlobalMaxPooling2… │                   │            │                   │
# ├─────────────────────┼───────────────────┼────────────┼───────────────────┤
# │ concatenate_2       │ (None, 128)       │          0 │ global_average_p… │
# │ (Concatenate)       │                   │            │ global_max_pooli… │
# ├─────────────────────┼───────────────────┼────────────┼───────────────────┤
# │ dense (Dense)       │ (None, 128)       │     16,512 │ concatenate_2[0]… │
# ├─────────────────────┼───────────────────┼────────────┼───────────────────┤
# │ dropout (Dropout)   │ (None, 128)       │          0 │ dense[0][0]       │
# ├─────────────────────┼───────────────────┼────────────┼───────────────────┤
# │ dense_1 (Dense)     │ (None, 64)        │      8,256 │ dropout[0][0]     │
# ├─────────────────────┼───────────────────┼────────────┼───────────────────┤
# │ dense_2 (Dense)     │ (None, 1)         │         65 │ dense_1[0][0]     │
# └─────────────────────┴───────────────────┴────────────┴───────────────────┘
#  Total params: 948,801 (3.62 MB)
#  Trainable params: 948,801 (3.62 MB)
#  Non-trainable params: 0 (0.00 B)
# 2026-09-06 18:54:04.845081: W external/local_xla/xla/tsl/framework/cpu_allocator_impl.cc:84] Allocation of 3657120000 exceeds 10% of free system memory.
# 2026-09-06 18:54:08.952300: W external/local_xla/xla/tsl/framework/cpu_allocator_impl.cc:84] Allocation of 3657120000 exceeds 10% of free system memory.
# Epoch 1/50
# 2026-09-06 18:54:14.207284: I external/local_xla/xla/service/service.cc:163] XLA service 0x7b9f200927d0 initialized for platform CUDA (this does not guarantee that XLA will be used). Devices:
# 2026-09-06 18:54:14.207314: I external/local_xla/xla/service/service.cc:171]   StreamExecutor device (0): Tesla T4, Compute Capability 7.5
# 2026-09-06 18:54:14.392282: I tensorflow/compiler/mlir/tensorflow/utils/dump_mlir_util.cc:269] disabling MLIR crash reproducer, set env var `MLIR_CRASH_REPRODUCER_DIRECTORY` to enable.
# 2026-09-06 18:54:14.988870: I external/local_xla/xla/stream_executor/cuda/cuda_dnn.cc:473] Loaded cuDNN version 91900
# 2026-09-06 18:54:16.347359: I external/local_xla/xla/service/gpu/autotuning/conv_algorithm_picker.cc:546] Omitted potentially buggy algorithm eng14{k25=2} for conv (f32[128,64,100,100]{3,2,1,0}, u8[0]{0}) custom-call(f32[128,3,100,100]{3,2,1,0}, f32[64,3,3,3]{3,2,1,0}, f32[64]{0}), window={size=3x3 pad=1_1x1_1}, dim_labels=bf01_oi01->bf01, custom_call_target="__cudnn$convBiasActivationForward", backend_config={"operation_queue_id":"0","wait_on_operation_queues":[],"cudnn_conv_backend_config":{"activation_mode":"kNone","conv_result_scale":1,"side_input_scale":0,"leakyrelu_alpha":0},"force_earliest_schedule":false,"reification_cost":[]}
# 2026-09-06 18:54:16.515712: I external/local_xla/xla/service/gpu/autotuning/conv_algorithm_picker.cc:546] Omitted potentially buggy algorithm eng14{k25=2} for conv (f32[128,128,50,50]{3,2,1,0}, u8[0]{0}) custom-call(f32[128,64,50,50]{3,2,1,0}, f32[128,64,3,3]{3,2,1,0}, f32[128]{0}), window={size=3x3 pad=1_1x1_1}, dim_labels=bf01_oi01->bf01, custom_call_target="__cudnn$convBiasActivationForward", backend_config={"operation_queue_id":"0","wait_on_operation_queues":[],"cudnn_conv_backend_config":{"activation_mode":"kNone","conv_result_scale":1,"side_input_scale":0,"leakyrelu_alpha":0},"force_earliest_schedule":false,"reification_cost":[]}
# 2026-09-06 18:54:17.335744: I external/local_xla/xla/service/gpu/autotuning/conv_algorithm_picker.cc:546] Omitted potentially buggy algorithm eng14{k25=2} for conv (f32[128,256,25,25]{3,2,1,0}, u8[0]{0}) custom-call(f32[128,128,25,25]{3,2,1,0}, f32[256,128,3,3]{3,2,1,0}, f32[256]{0}), window={size=3x3 pad=1_1x1_1}, dim_labels=bf01_oi01->bf01, custom_call_target="__cudnn$convBiasActivationForward", backend_config={"operation_queue_id":"0","wait_on_operation_queues":[],"cudnn_conv_backend_config":{"activation_mode":"kNone","conv_result_scale":1,"side_input_scale":0,"leakyrelu_alpha":0},"force_earliest_schedule":false,"reification_cost":[]}
# 2026-09-06 18:54:18.122810: I external/local_xla/xla/service/gpu/autotuning/conv_algorithm_picker.cc:546] Omitted potentially buggy algorithm eng14{k25=2} for conv (f32[128,128,50,50]{3,2,1,0}, u8[0]{0}) custom-call(f32[128,384,50,50]{3,2,1,0}, f32[128,384,3,3]{3,2,1,0}, f32[128]{0}), window={size=3x3 pad=1_1x1_1}, dim_labels=bf01_oi01->bf01, custom_call_target="__cudnn$convBiasActivationForward", backend_config={"operation_queue_id":"0","wait_on_operation_queues":[],"cudnn_conv_backend_config":{"activation_mode":"kNone","conv_result_scale":1,"side_input_scale":0,"leakyrelu_alpha":0},"force_earliest_schedule":false,"reification_cost":[]}
# 2026-09-06 18:54:21.881247: I external/local_xla/xla/service/gpu/autotuning/conv_algorithm_picker.cc:546] Omitted potentially buggy algorithm eng14{k25=2} for conv (f32[128,64,100,100]{3,2,1,0}, u8[0]{0}) custom-call(f32[128,192,100,100]{3,2,1,0}, f32[64,192,3,3]{3,2,1,0}, f32[64]{0}), window={size=3x3 pad=1_1x1_1}, dim_labels=bf01_oi01->bf01, custom_call_target="__cudnn$convBiasActivationForward", backend_config={"operation_queue_id":"0","wait_on_operation_queues":[],"cudnn_conv_backend_config":{"activation_mode":"kNone","conv_result_scale":1,"side_input_scale":0,"leakyrelu_alpha":0},"force_earliest_schedule":false,"reification_cost":[]}
# 2026-09-06 18:54:28.179894: E external/local_xla/xla/stream_executor/cuda/cuda_timer.cc:86] Delay kernel timed out: measured time has sub-optimal accuracy. There may be a missing warmup execution, please investigate in Nsight Systems.
# 2026-09-06 18:54:28.434125: E external/local_xla/xla/stream_executor/cuda/cuda_timer.cc:86] Delay kernel timed out: measured time has sub-optimal accuracy. There may be a missing warmup execution, please investigate in Nsight Systems.
# I0000 00:00:1788720891.063963   25803 device_compiler.h:196] Compiled cluster using XLA!  This line is logged at most once for the lifetime of the process.
# 2026-09-06 18:54:51.069247: W external/local_xla/xla/tsl/framework/bfc_allocator.cc:382] Garbage collection: deallocate free memory regions (i.e., allocations) so that we can re-allocate a larger region to avoid OOM due to memory fragmentation. If you see this message frequently, you are running near the threshold of the available device memory and re-allocation may incur great performance overhead. You may try smaller batch sizes to observe the performance impact. Set TF_ENABLE_GPU_GARBAGE_COLLECTION=false if you'd like to disable this feature.
# 2026-09-06 18:56:20.873367: I external/local_xla/xla/service/gpu/autotuning/conv_algorithm_picker.cc:546] Omitted potentially buggy algorithm eng14{k25=2} for conv (f32[12,64,100,100]{3,2,1,0}, u8[0]{0}) custom-call(f32[12,3,100,100]{3,2,1,0}, f32[64,3,3,3]{3,2,1,0}, f32[64]{0}), window={size=3x3 pad=1_1x1_1}, dim_labels=bf01_oi01->bf01, custom_call_target="__cudnn$convBiasActivationForward", backend_config={"operation_queue_id":"0","wait_on_operation_queues":[],"cudnn_conv_backend_config":{"activation_mode":"kNone","conv_result_scale":1,"side_input_scale":0,"leakyrelu_alpha":0},"force_earliest_schedule":false,"reification_cost":[]}
# 2026-09-06 18:56:20.893948: I external/local_xla/xla/service/gpu/autotuning/conv_algorithm_picker.cc:546] Omitted potentially buggy algorithm eng14{k25=2} for conv (f32[12,128,50,50]{3,2,1,0}, u8[0]{0}) custom-call(f32[12,64,50,50]{3,2,1,0}, f32[128,64,3,3]{3,2,1,0}, f32[128]{0}), window={size=3x3 pad=1_1x1_1}, dim_labels=bf01_oi01->bf01, custom_call_target="__cudnn$convBiasActivationForward", backend_config={"operation_queue_id":"0","wait_on_operation_queues":[],"cudnn_conv_backend_config":{"activation_mode":"kNone","conv_result_scale":1,"side_input_scale":0,"leakyrelu_alpha":0},"force_earliest_schedule":false,"reification_cost":[]}
# 2026-09-06 18:56:21.007867: I external/local_xla/xla/service/gpu/autotuning/conv_algorithm_picker.cc:546] Omitted potentially buggy algorithm eng14{k25=2} for conv (f32[12,256,25,25]{3,2,1,0}, u8[0]{0}) custom-call(f32[12,128,25,25]{3,2,1,0}, f32[256,128,3,3]{3,2,1,0}, f32[256]{0}), window={size=3x3 pad=1_1x1_1}, dim_labels=bf01_oi01->bf01, custom_call_target="__cudnn$convBiasActivationForward", backend_config={"operation_queue_id":"0","wait_on_operation_queues":[],"cudnn_conv_backend_config":{"activation_mode":"kNone","conv_result_scale":1,"side_input_scale":0,"leakyrelu_alpha":0},"force_earliest_schedule":false,"reification_cost":[]}
# 2026-09-06 18:56:21.101571: I external/local_xla/xla/service/gpu/autotuning/conv_algorithm_picker.cc:546] Omitted potentially buggy algorithm eng14{k25=2} for conv (f32[12,128,50,50]{3,2,1,0}, u8[0]{0}) custom-call(f32[12,384,50,50]{3,2,1,0}, f32[128,384,3,3]{3,2,1,0}, f32[128]{0}), window={size=3x3 pad=1_1x1_1}, dim_labels=bf01_oi01->bf01, custom_call_target="__cudnn$convBiasActivationForward", backend_config={"operation_queue_id":"0","wait_on_operation_queues":[],"cudnn_conv_backend_config":{"activation_mode":"kNone","conv_result_scale":1,"side_input_scale":0,"leakyrelu_alpha":0},"force_earliest_schedule":false,"reification_cost":[]}
# 2026-09-06 18:56:21.736087: I external/local_xla/xla/service/gpu/autotuning/conv_algorithm_picker.cc:546] Omitted potentially buggy algorithm eng14{k25=2} for conv (f32[12,64,100,100]{3,2,1,0}, u8[0]{0}) custom-call(f32[12,192,100,100]{3,2,1,0}, f32[64,192,3,3]{3,2,1,0}, f32[64]{0}), window={size=3x3 pad=1_1x1_1}, dim_labels=bf01_oi01->bf01, custom_call_target="__cudnn$convBiasActivationForward", backend_config={"operation_queue_id":"0","wait_on_operation_queues":[],"cudnn_conv_backend_config":{"activation_mode":"kNone","conv_result_scale":1,"side_input_scale":0,"leakyrelu_alpha":0},"force_earliest_schedule":false,"reification_cost":[]}
# 2026-09-06 18:56:23.101680: E external/local_xla/xla/stream_executor/cuda/cuda_timer.cc:86] Delay kernel timed out: measured time has sub-optimal accuracy. There may be a missing warmup execution, please investigate in Nsight Systems.
# 2026-09-06 18:56:23.278463: E external/local_xla/xla/stream_executor/cuda/cuda_timer.cc:86] Delay kernel timed out: measured time has sub-optimal accuracy. There may be a missing warmup execution, please investigate in Nsight Systems.
# 2026-09-06 18:56:28.815861: W external/local_xla/xla/tsl/framework/cpu_allocator_impl.cc:84] Allocation of 914280000 exceeds 10% of free system memory.
# 2026-09-06 18:56:29.724205: W external/local_xla/xla/tsl/framework/cpu_allocator_impl.cc:84] Allocation of 914280000 exceeds 10% of free system memory.
# 2026-09-06 18:56:31.086524: I external/local_xla/xla/service/gpu/autotuning/conv_algorithm_picker.cc:546] Omitted potentially buggy algorithm eng14{k25=2} for conv (f32[128,64,100,100]{3,2,1,0}, u8[0]{0}) custom-call(f32[128,3,100,100]{3,2,1,0}, f32[64,3,3,3]{3,2,1,0}, f32[64]{0}), window={size=3x3 pad=1_1x1_1}, dim_labels=bf01_oi01->bf01, custom_call_target="__cudnn$convBiasActivationForward", backend_config={"operation_queue_id":"0","wait_on_operation_queues":[],"cudnn_conv_backend_config":{"activation_mode":"kRelu","conv_result_scale":1,"side_input_scale":0,"leakyrelu_alpha":0},"force_earliest_schedule":false,"reification_cost":[]}
# 2026-09-06 18:56:31.190190: I external/local_xla/xla/service/gpu/autotuning/conv_algorithm_picker.cc:546] Omitted potentially buggy algorithm eng14{k25=2} for conv (f32[128,128,50,50]{3,2,1,0}, u8[0]{0}) custom-call(f32[128,64,50,50]{3,2,1,0}, f32[128,64,3,3]{3,2,1,0}, f32[128]{0}), window={size=3x3 pad=1_1x1_1}, dim_labels=bf01_oi01->bf01, custom_call_target="__cudnn$convBiasActivationForward", backend_config={"operation_queue_id":"0","wait_on_operation_queues":[],"cudnn_conv_backend_config":{"activation_mode":"kRelu","conv_result_scale":1,"side_input_scale":0,"leakyrelu_alpha":0},"force_earliest_schedule":false,"reification_cost":[]}
# 2026-09-06 18:56:32.277518: I external/local_xla/xla/service/gpu/autotuning/conv_algorithm_picker.cc:546] Omitted potentially buggy algorithm eng14{k25=2} for conv (f32[128,256,25,25]{3,2,1,0}, u8[0]{0}) custom-call(f32[128,128,25,25]{3,2,1,0}, f32[256,128,3,3]{3,2,1,0}, f32[256]{0}), window={size=3x3 pad=1_1x1_1}, dim_labels=bf01_oi01->bf01, custom_call_target="__cudnn$convBiasActivationForward", backend_config={"operation_queue_id":"0","wait_on_operation_queues":[],"cudnn_conv_backend_config":{"activation_mode":"kRelu","conv_result_scale":1,"side_input_scale":0,"leakyrelu_alpha":0},"force_earliest_schedule":false,"reification_cost":[]}
# 2026-09-06 18:56:33.084512: I external/local_xla/xla/service/gpu/autotuning/conv_algorithm_picker.cc:546] Omitted potentially buggy algorithm eng14{k25=2} for conv (f32[128,128,50,50]{3,2,1,0}, u8[0]{0}) custom-call(f32[128,384,50,50]{3,2,1,0}, f32[128,384,3,3]{3,2,1,0}, f32[128]{0}), window={size=3x3 pad=1_1x1_1}, dim_labels=bf01_oi01->bf01, custom_call_target="__cudnn$convBiasActivationForward", backend_config={"operation_queue_id":"0","wait_on_operation_queues":[],"cudnn_conv_backend_config":{"activation_mode":"kRelu","conv_result_scale":1,"side_input_scale":0,"leakyrelu_alpha":0},"force_earliest_schedule":false,"reification_cost":[]}
# 2026-09-06 18:56:37.314260: I external/local_xla/xla/service/gpu/autotuning/conv_algorithm_picker.cc:546] Omitted potentially buggy algorithm eng14{k25=2} for conv (f32[128,64,100,100]{3,2,1,0}, u8[0]{0}) custom-call(f32[128,192,100,100]{3,2,1,0}, f32[64,192,3,3]{3,2,1,0}, f32[64]{0}), window={size=3x3 pad=1_1x1_1}, dim_labels=bf01_oi01->bf01, custom_call_target="__cudnn$convBiasActivationForward", backend_config={"operation_queue_id":"0","wait_on_operation_queues":[],"cudnn_conv_backend_config":{"activation_mode":"kRelu","conv_result_scale":1,"side_input_scale":0,"leakyrelu_alpha":0},"force_earliest_schedule":false,"reification_cost":[]}
# 2026-09-06 18:56:50.971081: I external/local_xla/xla/service/gpu/autotuning/conv_algorithm_picker.cc:546] Omitted potentially buggy algorithm eng14{k25=2} for conv (f32[67,64,100,100]{3,2,1,0}, u8[0]{0}) custom-call(f32[67,3,100,100]{3,2,1,0}, f32[64,3,3,3]{3,2,1,0}, f32[64]{0}), window={size=3x3 pad=1_1x1_1}, dim_labels=bf01_oi01->bf01, custom_call_target="__cudnn$convBiasActivationForward", backend_config={"operation_queue_id":"0","wait_on_operation_queues":[],"cudnn_conv_backend_config":{"activation_mode":"kRelu","conv_result_scale":1,"side_input_scale":0,"leakyrelu_alpha":0},"force_earliest_schedule":false,"reification_cost":[]}
# 2026-09-06 18:56:51.039775: I external/local_xla/xla/service/gpu/autotuning/conv_algorithm_picker.cc:546] Omitted potentially buggy algorithm eng14{k25=2} for conv (f32[67,128,50,50]{3,2,1,0}, u8[0]{0}) custom-call(f32[67,64,50,50]{3,2,1,0}, f32[128,64,3,3]{3,2,1,0}, f32[128]{0}), window={size=3x3 pad=1_1x1_1}, dim_labels=bf01_oi01->bf01, custom_call_target="__cudnn$convBiasActivationForward", backend_config={"operation_queue_id":"0","wait_on_operation_queues":[],"cudnn_conv_backend_config":{"activation_mode":"kRelu","conv_result_scale":1,"side_input_scale":0,"leakyrelu_alpha":0},"force_earliest_schedule":false,"reification_cost":[]}
# 2026-09-06 18:56:51.541795: I external/local_xla/xla/service/gpu/autotuning/conv_algorithm_picker.cc:546] Omitted potentially buggy algorithm eng14{k25=2} for conv (f32[67,256,25,25]{3,2,1,0}, u8[0]{0}) custom-call(f32[67,128,25,25]{3,2,1,0}, f32[256,128,3,3]{3,2,1,0}, f32[256]{0}), window={size=3x3 pad=1_1x1_1}, dim_labels=bf01_oi01->bf01, custom_call_target="__cudnn$convBiasActivationForward", backend_config={"operation_queue_id":"0","wait_on_operation_queues":[],"cudnn_conv_backend_config":{"activation_mode":"kRelu","conv_result_scale":1,"side_input_scale":0,"leakyrelu_alpha":0},"force_earliest_schedule":false,"reification_cost":[]}
# 2026-09-06 18:56:51.937361: I external/local_xla/xla/service/gpu/autotuning/conv_algorithm_picker.cc:546] Omitted potentially buggy algorithm eng14{k25=2} for conv (f32[67,128,50,50]{3,2,1,0}, u8[0]{0}) custom-call(f32[67,384,50,50]{3,2,1,0}, f32[128,384,3,3]{3,2,1,0}, f32[128]{0}), window={size=3x3 pad=1_1x1_1}, dim_labels=bf01_oi01->bf01, custom_call_target="__cudnn$convBiasActivationForward", backend_config={"operation_queue_id":"0","wait_on_operation_queues":[],"cudnn_conv_backend_config":{"activation_mode":"kRelu","conv_result_scale":1,"side_input_scale":0,"leakyrelu_alpha":0},"force_earliest_schedule":false,"reification_cost":[]}
# 2026-09-06 18:56:54.651404: I external/local_xla/xla/service/gpu/autotuning/conv_algorithm_picker.cc:546] Omitted potentially buggy algorithm eng14{k25=2} for conv (f32[67,64,100,100]{3,2,1,0}, u8[0]{0}) custom-call(f32[67,192,100,100]{3,2,1,0}, f32[64,192,3,3]{3,2,1,0}, f32[64]{0}), window={size=3x3 pad=1_1x1_1}, dim_labels=bf01_oi01->bf01, custom_call_target="__cudnn$convBiasActivationForward", backend_config={"operation_queue_id":"0","wait_on_operation_queues":[],"cudnn_conv_backend_config":{"activation_mode":"kRelu","conv_result_scale":1,"side_input_scale":0,"leakyrelu_alpha":0},"force_earliest_schedule":false,"reification_cost":[]}
# 239/239 - 166s - 696ms/step - accuracy: 0.7205 - loss: 0.2249 - val_accuracy: 0.7658 - val_loss: 0.0353 - learning_rate: 0.0010
# Epoch 2/50
# 239/239 - 98s - 411ms/step - accuracy: 0.7837 - loss: 0.0300 - val_accuracy: 0.7584 - val_loss: 0.0320 - learning_rate: 0.0010
# Epoch 3/50
# 239/239 - 98s - 410ms/step - accuracy: 0.8061 - loss: 0.0274 - val_accuracy: 0.8092 - val_loss: 0.0265 - learning_rate: 0.0010
# Epoch 4/50
# 239/239 - 98s - 410ms/step - accuracy: 0.8215 - loss: 0.0255 - val_accuracy: 0.8103 - val_loss: 0.0268 - learning_rate: 0.0010
# Epoch 5/50
# 239/239 - 98s - 410ms/step - accuracy: 0.8289 - loss: 0.0246 - val_accuracy: 0.8148 - val_loss: 0.0253 - learning_rate: 0.0010
# Epoch 6/50
# 239/239 - 98s - 411ms/step - accuracy: 0.8388 - loss: 0.0238 - val_accuracy: 0.8369 - val_loss: 0.0238 - learning_rate: 0.0010
# Epoch 7/50
# 239/239 - 98s - 410ms/step - accuracy: 0.8435 - loss: 0.0231 - val_accuracy: 0.8367 - val_loss: 0.0232 - learning_rate: 0.0010
# Epoch 8/50
# 239/239 - 98s - 410ms/step - accuracy: 0.8473 - loss: 0.0225 - val_accuracy: 0.8382 - val_loss: 0.0233 - learning_rate: 0.0010
# Epoch 9/50
# 239/239 - 98s - 411ms/step - accuracy: 0.8514 - loss: 0.0220 - val_accuracy: 0.8489 - val_loss: 0.0223 - learning_rate: 0.0010
# Epoch 10/50
# 239/239 - 98s - 410ms/step - accuracy: 0.8565 - loss: 0.0214 - val_accuracy: 0.8392 - val_loss: 0.0226 - learning_rate: 0.0010
# Epoch 11/50
# 239/239 - 98s - 410ms/step - accuracy: 0.8592 - loss: 0.0210 - val_accuracy: 0.8540 - val_loss: 0.0214 - learning_rate: 0.0010
# Epoch 12/50
# 239/239 - 98s - 409ms/step - accuracy: 0.8641 - loss: 0.0202 - val_accuracy: 0.8474 - val_loss: 0.0232 - learning_rate: 0.0010
# Epoch 13/50
# 239/239 - 98s - 409ms/step - accuracy: 0.8697 - loss: 0.0200 - val_accuracy: 0.8534 - val_loss: 0.0216 - learning_rate: 0.0010
# Epoch 14/50
# 239/239 - 98s - 408ms/step - accuracy: 0.8727 - loss: 0.0194 - val_accuracy: 0.8537 - val_loss: 0.0222 - learning_rate: 0.0010
# Epoch 15/50
#
# Epoch 15: ReduceLROnPlateau reducing learning rate to 0.0005000000237487257.
# 239/239 - 98s - 409ms/step - accuracy: 0.8759 - loss: 0.0192 - val_accuracy: 0.8462 - val_loss: 0.0224 - learning_rate: 0.0010
# Epoch 16/50
# 239/239 - 98s - 409ms/step - accuracy: 0.8900 - loss: 0.0175 - val_accuracy: 0.8644 - val_loss: 0.0209 - learning_rate: 5.0000e-04
# Epoch 17/50
# 239/239 - 98s - 409ms/step - accuracy: 0.8950 - loss: 0.0165 - val_accuracy: 0.8631 - val_loss: 0.0205 - learning_rate: 5.0000e-04
# Epoch 18/50
# 239/239 - 98s - 409ms/step - accuracy: 0.8997 - loss: 0.0160 - val_accuracy: 0.8632 - val_loss: 0.0217 - learning_rate: 5.0000e-04
# Epoch 19/50
# 239/239 - 98s - 408ms/step - accuracy: 0.9036 - loss: 0.0155 - val_accuracy: 0.8668 - val_loss: 0.0212 - learning_rate: 5.0000e-04
# Epoch 20/50
# 239/239 - 97s - 408ms/step - accuracy: 0.9066 - loss: 0.0153 - val_accuracy: 0.8647 - val_loss: 0.0230 - learning_rate: 5.0000e-04
# Epoch 21/50
# 239/239 - 98s - 409ms/step - accuracy: 0.9082 - loss: 0.0147 - val_accuracy: 0.8626 - val_loss: 0.0205 - learning_rate: 5.0000e-04
# Epoch 22/50
# 239/239 - 98s - 409ms/step - accuracy: 0.9131 - loss: 0.0143 - val_accuracy: 0.8708 - val_loss: 0.0202 - learning_rate: 5.0000e-04
# Epoch 23/50
# 239/239 - 97s - 407ms/step - accuracy: 0.9156 - loss: 0.0139 - val_accuracy: 0.8731 - val_loss: 0.0207 - learning_rate: 5.0000e-04
# Epoch 24/50
# 239/239 - 97s - 407ms/step - accuracy: 0.9180 - loss: 0.0136 - val_accuracy: 0.8698 - val_loss: 0.0223 - learning_rate: 5.0000e-04
# Epoch 25/50
# 239/239 - 98s - 408ms/step - accuracy: 0.9217 - loss: 0.0130 - val_accuracy: 0.8731 - val_loss: 0.0222 - learning_rate: 5.0000e-04
# Epoch 26/50
# 239/239 - 97s - 407ms/step - accuracy: 0.9250 - loss: 0.0127 - val_accuracy: 0.8703 - val_loss: 0.0217 - learning_rate: 5.0000e-04
# Epoch 27/50
# 239/239 - 98s - 408ms/step - accuracy: 0.9269 - loss: 0.0125 - val_accuracy: 0.8757 - val_loss: 0.0221 - learning_rate: 5.0000e-04
# Epoch 28/50
# 239/239 - 98s - 409ms/step - accuracy: 0.9293 - loss: 0.0121 - val_accuracy: 0.8740 - val_loss: 0.0231 - learning_rate: 5.0000e-04
# Epoch 29/50
# 239/239 - 98s - 409ms/step - accuracy: 0.9313 - loss: 0.0119 - val_accuracy: 0.8747 - val_loss: 0.0231 - learning_rate: 5.0000e-04
# Epoch 30/50
# 239/239 - 98s - 410ms/step - accuracy: 0.9328 - loss: 0.0115 - val_accuracy: 0.8775 - val_loss: 0.0229 - learning_rate: 5.0000e-04
# Epoch 31/50
# 239/239 - 98s - 409ms/step - accuracy: 0.9329 - loss: 0.0116 - val_accuracy: 0.8785 - val_loss: 0.0225 - learning_rate: 5.0000e-04
# Epoch 32/50
# 239/239 - 98s - 409ms/step - accuracy: 0.9377 - loss: 0.0110 - val_accuracy: 0.8735 - val_loss: 0.0236 - learning_rate: 5.0000e-04
# Epoch 33/50
# 239/239 - 98s - 409ms/step - accuracy: 0.9370 - loss: 0.0109 - val_accuracy: 0.8777 - val_loss: 0.0244 - learning_rate: 5.0000e-04
# Epoch 34/50
# 239/239 - 98s - 409ms/step - accuracy: 0.9406 - loss: 0.0106 - val_accuracy: 0.8791 - val_loss: 0.0212 - learning_rate: 5.0000e-04
# Epoch 35/50
# 239/239 - 97s - 407ms/step - accuracy: 0.9400 - loss: 0.0104 - val_accuracy: 0.8740 - val_loss: 0.0239 - learning_rate: 5.0000e-04
# Epoch 36/50
# 239/239 - 97s - 408ms/step - accuracy: 0.9431 - loss: 0.0102 - val_accuracy: 0.8697 - val_loss: 0.0255 - learning_rate: 5.0000e-04
# Epoch 37/50
# 239/239 - 98s - 408ms/step - accuracy: 0.9449 - loss: 0.0099 - val_accuracy: 0.8731 - val_loss: 0.0287 - learning_rate: 5.0000e-04
# Epoch 38/50
#
# Epoch 38: ReduceLROnPlateau reducing learning rate to 0.0002500000118743628.
# 239/239 - 98s - 409ms/step - accuracy: 0.9451 - loss: 0.0097 - val_accuracy: 0.8779 - val_loss: 0.0247 - learning_rate: 5.0000e-04
# Epoch 39/50
# 239/239 - 98s - 409ms/step - accuracy: 0.9554 - loss: 0.0082 - val_accuracy: 0.8817 - val_loss: 0.0294 - learning_rate: 2.5000e-04
# Epoch 40/50
# 239/239 - 98s - 408ms/step - accuracy: 0.9559 - loss: 0.0080 - val_accuracy: 0.8796 - val_loss: 0.0289 - learning_rate: 2.5000e-04
# Epoch 41/50
# 239/239 - 98s - 409ms/step - accuracy: 0.9584 - loss: 0.0078 - val_accuracy: 0.8807 - val_loss: 0.0272 - learning_rate: 2.5000e-04
# Epoch 42/50
# 239/239 - 98s - 410ms/step - accuracy: 0.9584 - loss: 0.0078 - val_accuracy: 0.8798 - val_loss: 0.0284 - learning_rate: 2.5000e-04
# Epoch 43/50
# 239/239 - 98s - 409ms/step - accuracy: 0.9596 - loss: 0.0075 - val_accuracy: 0.8831 - val_loss: 0.0275 - learning_rate: 2.5000e-04
# Epoch 44/50
# 239/239 - 97s - 407ms/step - accuracy: 0.9593 - loss: 0.0074 - val_accuracy: 0.8808 - val_loss: 0.0301 - learning_rate: 2.5000e-04
# Epoch 45/50
# 239/239 - 97s - 408ms/step - accuracy: 0.9588 - loss: 0.0074 - val_accuracy: 0.8781 - val_loss: 0.0297 - learning_rate: 2.5000e-04
# Epoch 46/50
# 239/239 - 98s - 409ms/step - accuracy: 0.9603 - loss: 0.0073 - val_accuracy: 0.8827 - val_loss: 0.0286 - learning_rate: 2.5000e-04
# Epoch 47/50
#
# Epoch 47: ReduceLROnPlateau reducing learning rate to 0.0001250000059371814.
# 239/239 - 98s - 410ms/step - accuracy: 0.9609 - loss: 0.0073 - val_accuracy: 0.8817 - val_loss: 0.0295 - learning_rate: 2.5000e-04
# Epoch 48/50
# 239/239 - 98s - 408ms/step - accuracy: 0.9648 - loss: 0.0066 - val_accuracy: 0.8800 - val_loss: 0.0298 - learning_rate: 1.2500e-04
# Epoch 49/50
# 239/239 - 98s - 410ms/step - accuracy: 0.9656 - loss: 0.0064 - val_accuracy: 0.8845 - val_loss: 0.0342 - learning_rate: 1.2500e-04
# Epoch 50/50
# 239/239 - 98s - 410ms/step - accuracy: 0.9660 - loss: 0.0064 - val_accuracy: 0.8819 - val_loss: 0.0313 - learning_rate: 1.2500e-04
# Plot saved to /content/smartbugs-wild-with-content-and-result/output/training_plot_unet_only.png
# Figure(1000x600)
# 2026-09-06 20:16:49.220391: W external/local_xla/xla/tsl/framework/cpu_allocator_impl.cc:84] Allocation of 1142880000 exceeds 10% of free system memory.
# 2026-09-06 20:16:51.713584: I external/local_xla/xla/service/gpu/autotuning/conv_algorithm_picker.cc:546] Omitted potentially buggy algorithm eng14{k25=2} for conv (f32[32,64,100,100]{3,2,1,0}, u8[0]{0}) custom-call(f32[32,3,100,100]{3,2,1,0}, f32[64,3,3,3]{3,2,1,0}, f32[64]{0}), window={size=3x3 pad=1_1x1_1}, dim_labels=bf01_oi01->bf01, custom_call_target="__cudnn$convBiasActivationForward", backend_config={"operation_queue_id":"0","wait_on_operation_queues":[],"cudnn_conv_backend_config":{"activation_mode":"kRelu","conv_result_scale":1,"side_input_scale":0,"leakyrelu_alpha":0},"force_earliest_schedule":false,"reification_cost":[]}
# 2026-09-06 20:16:51.758303: I external/local_xla/xla/service/gpu/autotuning/conv_algorithm_picker.cc:546] Omitted potentially buggy algorithm eng14{k25=2} for conv (f32[32,128,50,50]{3,2,1,0}, u8[0]{0}) custom-call(f32[32,64,50,50]{3,2,1,0}, f32[128,64,3,3]{3,2,1,0}, f32[128]{0}), window={size=3x3 pad=1_1x1_1}, dim_labels=bf01_oi01->bf01, custom_call_target="__cudnn$convBiasActivationForward", backend_config={"operation_queue_id":"0","wait_on_operation_queues":[],"cudnn_conv_backend_config":{"activation_mode":"kRelu","conv_result_scale":1,"side_input_scale":0,"leakyrelu_alpha":0},"force_earliest_schedule":false,"reification_cost":[]}
# 2026-09-06 20:16:52.008308: I external/local_xla/xla/service/gpu/autotuning/conv_algorithm_picker.cc:546] Omitted potentially buggy algorithm eng14{k25=2} for conv (f32[32,256,25,25]{3,2,1,0}, u8[0]{0}) custom-call(f32[32,128,25,25]{3,2,1,0}, f32[256,128,3,3]{3,2,1,0}, f32[256]{0}), window={size=3x3 pad=1_1x1_1}, dim_labels=bf01_oi01->bf01, custom_call_target="__cudnn$convBiasActivationForward", backend_config={"operation_queue_id":"0","wait_on_operation_queues":[],"cudnn_conv_backend_config":{"activation_mode":"kRelu","conv_result_scale":1,"side_input_scale":0,"leakyrelu_alpha":0},"force_earliest_schedule":false,"reification_cost":[]}
# 2026-09-06 20:16:52.204983: I external/local_xla/xla/service/gpu/autotuning/conv_algorithm_picker.cc:546] Omitted potentially buggy algorithm eng14{k25=2} for conv (f32[32,128,50,50]{3,2,1,0}, u8[0]{0}) custom-call(f32[32,384,50,50]{3,2,1,0}, f32[128,384,3,3]{3,2,1,0}, f32[128]{0}), window={size=3x3 pad=1_1x1_1}, dim_labels=bf01_oi01->bf01, custom_call_target="__cudnn$convBiasActivationForward", backend_config={"operation_queue_id":"0","wait_on_operation_queues":[],"cudnn_conv_backend_config":{"activation_mode":"kRelu","conv_result_scale":1,"side_input_scale":0,"leakyrelu_alpha":0},"force_earliest_schedule":false,"reification_cost":[]}
# 2026-09-06 20:16:54.151566: I external/local_xla/xla/service/gpu/autotuning/conv_algorithm_picker.cc:546] Omitted potentially buggy algorithm eng14{k25=2} for conv (f32[32,64,100,100]{3,2,1,0}, u8[0]{0}) custom-call(f32[32,192,100,100]{3,2,1,0}, f32[64,192,3,3]{3,2,1,0}, f32[64]{0}), window={size=3x3 pad=1_1x1_1}, dim_labels=bf01_oi01->bf01, custom_call_target="__cudnn$convBiasActivationForward", backend_config={"operation_queue_id":"0","wait_on_operation_queues":[],"cudnn_conv_backend_config":{"activation_mode":"kRelu","conv_result_scale":1,"side_input_scale":0,"leakyrelu_alpha":0},"force_earliest_schedule":false,"reification_cost":[]}
# 297/298 ━━━━━━━━━━━━━━━━━━━━ 0s 37ms/step2026-09-06 20:17:07.862079: I external/local_xla/xla/service/gpu/autotuning/conv_algorithm_picker.cc:546] Omitted potentially buggy algorithm eng14{k25=2} for conv (f32[20,64,100,100]{3,2,1,0}, u8[0]{0}) custom-call(f32[20,3,100,100]{3,2,1,0}, f32[64,3,3,3]{3,2,1,0}, f32[64]{0}), window={size=3x3 pad=1_1x1_1}, dim_labels=bf01_oi01->bf01, custom_call_target="__cudnn$convBiasActivationForward", backend_config={"operation_queue_id":"0","wait_on_operation_queues":[],"cudnn_conv_backend_config":{"activation_mode":"kRelu","conv_result_scale":1,"side_input_scale":0,"leakyrelu_alpha":0},"force_earliest_schedule":false,"reification_cost":[]}
# 2026-09-06 20:17:07.896936: I external/local_xla/xla/service/gpu/autotuning/conv_algorithm_picker.cc:546] Omitted potentially buggy algorithm eng14{k25=2} for conv (f32[20,128,50,50]{3,2,1,0}, u8[0]{0}) custom-call(f32[20,64,50,50]{3,2,1,0}, f32[128,64,3,3]{3,2,1,0}, f32[128]{0}), window={size=3x3 pad=1_1x1_1}, dim_labels=bf01_oi01->bf01, custom_call_target="__cudnn$convBiasActivationForward", backend_config={"operation_queue_id":"0","wait_on_operation_queues":[],"cudnn_conv_backend_config":{"activation_mode":"kRelu","conv_result_scale":1,"side_input_scale":0,"leakyrelu_alpha":0},"force_earliest_schedule":false,"reification_cost":[]}
# 2026-09-06 20:17:08.045083: I external/local_xla/xla/service/gpu/autotuning/conv_algorithm_picker.cc:546] Omitted potentially buggy algorithm eng14{k25=2} for conv (f32[20,256,25,25]{3,2,1,0}, u8[0]{0}) custom-call(f32[20,128,25,25]{3,2,1,0}, f32[256,128,3,3]{3,2,1,0}, f32[256]{0}), window={size=3x3 pad=1_1x1_1}, dim_labels=bf01_oi01->bf01, custom_call_target="__cudnn$convBiasActivationForward", backend_config={"operation_queue_id":"0","wait_on_operation_queues":[],"cudnn_conv_backend_config":{"activation_mode":"kRelu","conv_result_scale":1,"side_input_scale":0,"leakyrelu_alpha":0},"force_earliest_schedule":false,"reification_cost":[]}
# 2026-09-06 20:17:08.185041: I external/local_xla/xla/service/gpu/autotuning/conv_algorithm_picker.cc:546] Omitted potentially buggy algorithm eng14{k25=2} for conv (f32[20,128,50,50]{3,2,1,0}, u8[0]{0}) custom-call(f32[20,384,50,50]{3,2,1,0}, f32[128,384,3,3]{3,2,1,0}, f32[128]{0}), window={size=3x3 pad=1_1x1_1}, dim_labels=bf01_oi01->bf01, custom_call_target="__cudnn$convBiasActivationForward", backend_config={"operation_queue_id":"0","wait_on_operation_queues":[],"cudnn_conv_backend_config":{"activation_mode":"kRelu","conv_result_scale":1,"side_input_scale":0,"leakyrelu_alpha":0},"force_earliest_schedule":false,"reification_cost":[]}
# 2026-09-06 20:17:09.412952: I external/local_xla/xla/service/gpu/autotuning/conv_algorithm_picker.cc:546] Omitted potentially buggy algorithm eng14{k25=2} for conv (f32[20,64,100,100]{3,2,1,0}, u8[0]{0}) custom-call(f32[20,192,100,100]{3,2,1,0}, f32[64,192,3,3]{3,2,1,0}, f32[64]{0}), window={size=3x3 pad=1_1x1_1}, dim_labels=bf01_oi01->bf01, custom_call_target="__cudnn$convBiasActivationForward", backend_config={"operation_queue_id":"0","wait_on_operation_queues":[],"cudnn_conv_backend_config":{"activation_mode":"kRelu","conv_result_scale":1,"side_input_scale":0,"leakyrelu_alpha":0},"force_earliest_schedule":false,"reification_cost":[]}
# 298/298 ━━━━━━━━━━━━━━━━━━━━ 20s 49ms/step
#
# ==================================================
# U-Net-only accuracy:       0.8852
# Majority-class baseline:   0.5967
# Improvement over baseline: 28.85%
# ==================================================
#
# Classification Report:
#               precision    recall  f1-score   support
#
#         Safe       0.90      0.90      0.90      5683
#   Vulnerable       0.86      0.86      0.86      3841
#
#     accuracy                           0.89      9524
#    macro avg       0.88      0.88      0.88      9524
# weighted avg       0.89      0.89      0.89      9524
#
# Model saved to /content/smartbugs-wild-with-content-and-result/output/final_unet_only_model.keras

# -------------------------------------------------
# 2026-09-06 20:31:46.261718: I tensorflow/core/platform/cpu_feature_guard.cc:210] This TensorFlow binary is optimized to use available CPU instructions in performance-critical operations.
# To enable the following instructions: AVX2 AVX512F FMA, in other operations, rebuild TensorFlow with the appropriate compiler flags.
# 2026-09-06 20:32:35.554918: W tensorflow/core/common_runtime/gpu/gpu_bfc_allocator.cc:47] Overriding orig_value setting because the TF_FORCE_GPU_ALLOW_GROWTH environment variable is set. Original config value was 0.
# WARNING: All log messages before absl::InitializeLog() is called are written to STDERR
# I0000 00:00:1788726755.556461   52235 gpu_device.cc:2020] Created device /job:localhost/replica:0/task:0/device:GPU:0 with 13757 MB memory:  -> device: 0, name: Tesla T4, pci bus id: 0000:00:04.0, compute capability: 7.5
# در حال پیش‌بینی با مدل‌های پایه روی داده train...
# 2026-09-06 20:32:43.217751: W external/local_xla/xla/tsl/framework/cpu_allocator_impl.cc:84] Allocation of 4571400000 exceeds 10% of free system memory.
# 2026-09-06 20:32:47.943680: W external/local_xla/xla/tsl/framework/cpu_allocator_impl.cc:84] Allocation of 4571400000 exceeds 10% of free system memory.
# 2026-09-06 20:32:51.571191: I external/local_xla/xla/stream_executor/cuda/cuda_dnn.cc:473] Loaded cuDNN version 91900
# 1191/1191 ━━━━━━━━━━━━━━━━━━━━ 11s 8ms/step
# 2026-09-06 20:33:04.914845: W external/local_xla/xla/tsl/framework/cpu_allocator_impl.cc:84] Allocation of 4571400000 exceeds 10% of free system memory.
# 2026-09-06 20:33:09.309915: W external/local_xla/xla/tsl/framework/cpu_allocator_impl.cc:84] Allocation of 4571400000 exceeds 10% of free system memory.
# 2026-09-06 20:33:12.739788: I external/local_xla/xla/service/service.cc:163] XLA service 0x7ab52b01c790 initialized for platform CUDA (this does not guarantee that XLA will be used). Devices:
# 2026-09-06 20:33:12.739820: I external/local_xla/xla/service/service.cc:171]   StreamExecutor device (0): Tesla T4, Compute Capability 7.5
# 2026-09-06 20:33:12.782795: I tensorflow/compiler/mlir/tensorflow/utils/dump_mlir_util.cc:269] disabling MLIR crash reproducer, set env var `MLIR_CRASH_REPRODUCER_DIRECTORY` to enable.
# 2026-09-06 20:33:13.575494: I external/local_xla/xla/service/gpu/autotuning/conv_algorithm_picker.cc:546] Omitted potentially buggy algorithm eng14{k25=2} for conv (f32[32,64,100,100]{3,2,1,0}, u8[0]{0}) custom-call(f32[32,3,100,100]{3,2,1,0}, f32[64,3,3,3]{3,2,1,0}, f32[64]{0}), window={size=3x3 pad=1_1x1_1}, dim_labels=bf01_oi01->bf01, custom_call_target="__cudnn$convBiasActivationForward", backend_config={"operation_queue_id":"0","wait_on_operation_queues":[],"cudnn_conv_backend_config":{"activation_mode":"kRelu","conv_result_scale":1,"side_input_scale":0,"leakyrelu_alpha":0},"force_earliest_schedule":false,"reification_cost":[]}
# 2026-09-06 20:33:13.685244: I external/local_xla/xla/service/gpu/autotuning/conv_algorithm_picker.cc:546] Omitted potentially buggy algorithm eng14{k25=2} for conv (f32[32,128,50,50]{3,2,1,0}, u8[0]{0}) custom-call(f32[32,64,50,50]{3,2,1,0}, f32[128,64,3,3]{3,2,1,0}, f32[128]{0}), window={size=3x3 pad=1_1x1_1}, dim_labels=bf01_oi01->bf01, custom_call_target="__cudnn$convBiasActivationForward", backend_config={"operation_queue_id":"0","wait_on_operation_queues":[],"cudnn_conv_backend_config":{"activation_mode":"kRelu","conv_result_scale":1,"side_input_scale":0,"leakyrelu_alpha":0},"force_earliest_schedule":false,"reification_cost":[]}
# 2026-09-06 20:33:13.979894: I external/local_xla/xla/service/gpu/autotuning/conv_algorithm_picker.cc:546] Omitted potentially buggy algorithm eng14{k25=2} for conv (f32[32,256,25,25]{3,2,1,0}, u8[0]{0}) custom-call(f32[32,128,25,25]{3,2,1,0}, f32[256,128,3,3]{3,2,1,0}, f32[256]{0}), window={size=3x3 pad=1_1x1_1}, dim_labels=bf01_oi01->bf01, custom_call_target="__cudnn$convBiasActivationForward", backend_config={"operation_queue_id":"0","wait_on_operation_queues":[],"cudnn_conv_backend_config":{"activation_mode":"kRelu","conv_result_scale":1,"side_input_scale":0,"leakyrelu_alpha":0},"force_earliest_schedule":false,"reification_cost":[]}
# 2026-09-06 20:33:14.156585: I external/local_xla/xla/service/gpu/autotuning/conv_algorithm_picker.cc:546] Omitted potentially buggy algorithm eng14{k25=2} for conv (f32[32,128,50,50]{3,2,1,0}, u8[0]{0}) custom-call(f32[32,384,50,50]{3,2,1,0}, f32[128,384,3,3]{3,2,1,0}, f32[128]{0}), window={size=3x3 pad=1_1x1_1}, dim_labels=bf01_oi01->bf01, custom_call_target="__cudnn$convBiasActivationForward", backend_config={"operation_queue_id":"0","wait_on_operation_queues":[],"cudnn_conv_backend_config":{"activation_mode":"kRelu","conv_result_scale":1,"side_input_scale":0,"leakyrelu_alpha":0},"force_earliest_schedule":false,"reification_cost":[]}
# 2026-09-06 20:33:15.522143: I external/local_xla/xla/service/gpu/autotuning/conv_algorithm_picker.cc:546] Omitted potentially buggy algorithm eng14{k25=2} for conv (f32[32,64,100,100]{3,2,1,0}, u8[0]{0}) custom-call(f32[32,192,100,100]{3,2,1,0}, f32[64,192,3,3]{3,2,1,0}, f32[64]{0}), window={size=3x3 pad=1_1x1_1}, dim_labels=bf01_oi01->bf01, custom_call_target="__cudnn$convBiasActivationForward", backend_config={"operation_queue_id":"0","wait_on_operation_queues":[],"cudnn_conv_backend_config":{"activation_mode":"kRelu","conv_result_scale":1,"side_input_scale":0,"leakyrelu_alpha":0},"force_earliest_schedule":false,"reification_cost":[]}
# I0000 00:00:1788726797.644861   52516 device_compiler.h:196] Compiled cluster using XLA!  This line is logged at most once for the lifetime of the process.
# 1189/1191 ━━━━━━━━━━━━━━━━━━━━ 0s 33ms/step2026-09-06 20:33:57.474154: I external/local_xla/xla/service/gpu/autotuning/conv_algorithm_picker.cc:546] Omitted potentially buggy algorithm eng14{k25=2} for conv (f32[15,64,100,100]{3,2,1,0}, u8[0]{0}) custom-call(f32[15,3,100,100]{3,2,1,0}, f32[64,3,3,3]{3,2,1,0}, f32[64]{0}), window={size=3x3 pad=1_1x1_1}, dim_labels=bf01_oi01->bf01, custom_call_target="__cudnn$convBiasActivationForward", backend_config={"operation_queue_id":"0","wait_on_operation_queues":[],"cudnn_conv_backend_config":{"activation_mode":"kRelu","conv_result_scale":1,"side_input_scale":0,"leakyrelu_alpha":0},"force_earliest_schedule":false,"reification_cost":[]}
# 2026-09-06 20:33:57.522983: I external/local_xla/xla/service/gpu/autotuning/conv_algorithm_picker.cc:546] Omitted potentially buggy algorithm eng14{k25=2} for conv (f32[15,128,50,50]{3,2,1,0}, u8[0]{0}) custom-call(f32[15,64,50,50]{3,2,1,0}, f32[128,64,3,3]{3,2,1,0}, f32[128]{0}), window={size=3x3 pad=1_1x1_1}, dim_labels=bf01_oi01->bf01, custom_call_target="__cudnn$convBiasActivationForward", backend_config={"operation_queue_id":"0","wait_on_operation_queues":[],"cudnn_conv_backend_config":{"activation_mode":"kRelu","conv_result_scale":1,"side_input_scale":0,"leakyrelu_alpha":0},"force_earliest_schedule":false,"reification_cost":[]}
# 2026-09-06 20:33:57.642132: I external/local_xla/xla/service/gpu/autotuning/conv_algorithm_picker.cc:546] Omitted potentially buggy algorithm eng14{k25=2} for conv (f32[15,256,25,25]{3,2,1,0}, u8[0]{0}) custom-call(f32[15,128,25,25]{3,2,1,0}, f32[256,128,3,3]{3,2,1,0}, f32[256]{0}), window={size=3x3 pad=1_1x1_1}, dim_labels=bf01_oi01->bf01, custom_call_target="__cudnn$convBiasActivationForward", backend_config={"operation_queue_id":"0","wait_on_operation_queues":[],"cudnn_conv_backend_config":{"activation_mode":"kRelu","conv_result_scale":1,"side_input_scale":0,"leakyrelu_alpha":0},"force_earliest_schedule":false,"reification_cost":[]}
# 2026-09-06 20:33:57.752116: I external/local_xla/xla/service/gpu/autotuning/conv_algorithm_picker.cc:546] Omitted potentially buggy algorithm eng14{k25=2} for conv (f32[15,128,50,50]{3,2,1,0}, u8[0]{0}) custom-call(f32[15,384,50,50]{3,2,1,0}, f32[128,384,3,3]{3,2,1,0}, f32[128]{0}), window={size=3x3 pad=1_1x1_1}, dim_labels=bf01_oi01->bf01, custom_call_target="__cudnn$convBiasActivationForward", backend_config={"operation_queue_id":"0","wait_on_operation_queues":[],"cudnn_conv_backend_config":{"activation_mode":"kRelu","conv_result_scale":1,"side_input_scale":0,"leakyrelu_alpha":0},"force_earliest_schedule":false,"reification_cost":[]}
# 2026-09-06 20:33:58.622486: I external/local_xla/xla/service/gpu/autotuning/conv_algorithm_picker.cc:546] Omitted potentially buggy algorithm eng14{k25=2} for conv (f32[15,64,100,100]{3,2,1,0}, u8[0]{0}) custom-call(f32[15,192,100,100]{3,2,1,0}, f32[64,192,3,3]{3,2,1,0}, f32[64]{0}), window={size=3x3 pad=1_1x1_1}, dim_labels=bf01_oi01->bf01, custom_call_target="__cudnn$convBiasActivationForward", backend_config={"operation_queue_id":"0","wait_on_operation_queues":[],"cudnn_conv_backend_config":{"activation_mode":"kRelu","conv_result_scale":1,"side_input_scale":0,"leakyrelu_alpha":0},"force_earliest_schedule":false,"reification_cost":[]}
# 1191/1191 ━━━━━━━━━━━━━━━━━━━━ 47s 35ms/step
# در حال پیش‌بینی با مدل‌های پایه روی داده test...
# 2026-09-06 20:34:01.094289: W external/local_xla/xla/tsl/framework/cpu_allocator_impl.cc:84] Allocation of 1142880000 exceeds 10% of free system memory.
# 298/298 ━━━━━━━━━━━━━━━━━━━━ 2s 8ms/step
# 297/298 ━━━━━━━━━━━━━━━━━━━━ 0s 35ms/step2026-09-06 20:34:18.800104: I external/local_xla/xla/service/gpu/autotuning/conv_algorithm_picker.cc:546] Omitted potentially buggy algorithm eng14{k25=2} for conv (f32[20,64,100,100]{3,2,1,0}, u8[0]{0}) custom-call(f32[20,3,100,100]{3,2,1,0}, f32[64,3,3,3]{3,2,1,0}, f32[64]{0}), window={size=3x3 pad=1_1x1_1}, dim_labels=bf01_oi01->bf01, custom_call_target="__cudnn$convBiasActivationForward", backend_config={"operation_queue_id":"0","wait_on_operation_queues":[],"cudnn_conv_backend_config":{"activation_mode":"kRelu","conv_result_scale":1,"side_input_scale":0,"leakyrelu_alpha":0},"force_earliest_schedule":false,"reification_cost":[]}
# 2026-09-06 20:34:18.833755: I external/local_xla/xla/service/gpu/autotuning/conv_algorithm_picker.cc:546] Omitted potentially buggy algorithm eng14{k25=2} for conv (f32[20,128,50,50]{3,2,1,0}, u8[0]{0}) custom-call(f32[20,64,50,50]{3,2,1,0}, f32[128,64,3,3]{3,2,1,0}, f32[128]{0}), window={size=3x3 pad=1_1x1_1}, dim_labels=bf01_oi01->bf01, custom_call_target="__cudnn$convBiasActivationForward", backend_config={"operation_queue_id":"0","wait_on_operation_queues":[],"cudnn_conv_backend_config":{"activation_mode":"kRelu","conv_result_scale":1,"side_input_scale":0,"leakyrelu_alpha":0},"force_earliest_schedule":false,"reification_cost":[]}
# 2026-09-06 20:34:18.981869: I external/local_xla/xla/service/gpu/autotuning/conv_algorithm_picker.cc:546] Omitted potentially buggy algorithm eng14{k25=2} for conv (f32[20,256,25,25]{3,2,1,0}, u8[0]{0}) custom-call(f32[20,128,25,25]{3,2,1,0}, f32[256,128,3,3]{3,2,1,0}, f32[256]{0}), window={size=3x3 pad=1_1x1_1}, dim_labels=bf01_oi01->bf01, custom_call_target="__cudnn$convBiasActivationForward", backend_config={"operation_queue_id":"0","wait_on_operation_queues":[],"cudnn_conv_backend_config":{"activation_mode":"kRelu","conv_result_scale":1,"side_input_scale":0,"leakyrelu_alpha":0},"force_earliest_schedule":false,"reification_cost":[]}
# 2026-09-06 20:34:19.139779: I external/local_xla/xla/service/gpu/autotuning/conv_algorithm_picker.cc:546] Omitted potentially buggy algorithm eng14{k25=2} for conv (f32[20,128,50,50]{3,2,1,0}, u8[0]{0}) custom-call(f32[20,384,50,50]{3,2,1,0}, f32[128,384,3,3]{3,2,1,0}, f32[128]{0}), window={size=3x3 pad=1_1x1_1}, dim_labels=bf01_oi01->bf01, custom_call_target="__cudnn$convBiasActivationForward", backend_config={"operation_queue_id":"0","wait_on_operation_queues":[],"cudnn_conv_backend_config":{"activation_mode":"kRelu","conv_result_scale":1,"side_input_scale":0,"leakyrelu_alpha":0},"force_earliest_schedule":false,"reification_cost":[]}
# 2026-09-06 20:34:20.138915: I external/local_xla/xla/service/gpu/autotuning/conv_algorithm_picker.cc:546] Omitted potentially buggy algorithm eng14{k25=2} for conv (f32[20,64,100,100]{3,2,1,0}, u8[0]{0}) custom-call(f32[20,192,100,100]{3,2,1,0}, f32[64,192,3,3]{3,2,1,0}, f32[64]{0}), window={size=3x3 pad=1_1x1_1}, dim_labels=bf01_oi01->bf01, custom_call_target="__cudnn$convBiasActivationForward", backend_config={"operation_queue_id":"0","wait_on_operation_queues":[],"cudnn_conv_backend_config":{"activation_mode":"kRelu","conv_result_scale":1,"side_input_scale":0,"leakyrelu_alpha":0},"force_earliest_schedule":false,"reification_cost":[]}
# 298/298 ━━━━━━━━━━━━━━━━━━━━ 14s 47ms/step
# Epoch 1/50
# 239/239 - 3s - 12ms/step - accuracy: 0.8153 - loss: 0.0271 - val_accuracy: 0.8833 - val_loss: 0.0228
# Epoch 2/50
# 239/239 - 1s - 3ms/step - accuracy: 0.9698 - loss: 0.0114 - val_accuracy: 0.8867 - val_loss: 0.0198
# Epoch 3/50
# 239/239 - 1s - 3ms/step - accuracy: 0.9710 - loss: 0.0070 - val_accuracy: 0.8863 - val_loss: 0.0222
# Epoch 4/50
# 239/239 - 1s - 3ms/step - accuracy: 0.9709 - loss: 0.0060 - val_accuracy: 0.8857 - val_loss: 0.0246
# Epoch 5/50
# 239/239 - 1s - 3ms/step - accuracy: 0.9710 - loss: 0.0057 - val_accuracy: 0.8859 - val_loss: 0.0265
# Epoch 6/50
# 239/239 - 1s - 3ms/step - accuracy: 0.9709 - loss: 0.0056 - val_accuracy: 0.8858 - val_loss: 0.0275
# Epoch 7/50
# 239/239 - 1s - 3ms/step - accuracy: 0.9712 - loss: 0.0056 - val_accuracy: 0.8858 - val_loss: 0.0277
# Epoch 8/50
# 239/239 - 1s - 3ms/step - accuracy: 0.9711 - loss: 0.0056 - val_accuracy: 0.8849 - val_loss: 0.0275
# Epoch 9/50
# 239/239 - 1s - 3ms/step - accuracy: 0.9710 - loss: 0.0055 - val_accuracy: 0.8853 - val_loss: 0.0276
# Epoch 10/50
# 239/239 - 1s - 3ms/step - accuracy: 0.9710 - loss: 0.0055 - val_accuracy: 0.8855 - val_loss: 0.0280
# Epoch 11/50
# 239/239 - 1s - 3ms/step - accuracy: 0.9709 - loss: 0.0055 - val_accuracy: 0.8854 - val_loss: 0.0282
# Epoch 12/50
# 239/239 - 1s - 3ms/step - accuracy: 0.9710 - loss: 0.0055 - val_accuracy: 0.8854 - val_loss: 0.0282
# 298/298 ━━━━━━━━━━━━━━━━━━━━ 1s 2ms/step
#
# ==================================================
# Stacking Ensemble Accuracy: 0.8885
# ==================================================
#
# Classification Report:
#               precision    recall  f1-score   support
#
#         Safe       0.91      0.90      0.91      5683
#   Vulnerable       0.86      0.87      0.86      3841
#
#     accuracy                           0.89      9524
#    macro avg       0.88      0.88      0.88      9524
# weighted avg       0.89      0.89      0.89      9524
#
# Model saved to /content/smartbugs-wild-with-content-and-result/output/final_stacking_ensemble.keras