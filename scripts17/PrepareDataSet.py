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
import sys
import io
from tensorflow.keras import backend as K
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
from tensorflow.keras.models import Sequential
# from tensorflow.keras.layers import Conv1D, Bidirectional, LSTM, Dropout, Dense
from tensorflow.keras.layers import Embedding, Bidirectional, GRU, Dropout, Dense
from tensorflow.keras.callbacks import EarlyStopping

# from tensorflow.keras.optimizers import Adam
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



def load_batches():
    X_batches, Y_batches = [], []
    for file in os.listdir(CACHE_DIR):
        with open(os.path.join(CACHE_DIR, file), 'rb') as f:
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



def process_batch(files, target_vulnerability):
    X, Y = [], []
    max_function_length = 50  # تعداد گام‌های زمانی (طول فانکشن)
    for file in files:
        with open(file, encoding="utf8") as f:
            smartContractContent = f.read()

            # استخراج فانکشن‌ها و خطوط آسیب‌پذیر
            cleaned_smart_contract = PreProcessTools.clean_smart_contract(smartContractContent)
            functions = extract_functions_with_bodies(cleaned_smart_contract)
            name = Path(file).stem
            res, vulnerable_lines = getResultVulnarable(name, target_vulnerability)

            # لیبل‌گذاری
            label_functions_by_vulnerable_lines(functions, vulnerable_lines)

            # پردازش فانکشن‌ها
            for function in functions:
                fragments = PreProcessTools.get_fragments(function['function_body'])
                label = function['label']
                func_vectors = []
                for fragment in fragments:
                    if fragment.strip():
                        tokens = tokenize_solidity_code(fragment)

                        if tokens:  # بررسی کنید که آیا توکن‌ها خالی هستند یا خیر
                            vectors = vectorize_tokens(tokens)
                            func_vectors.extend(vectors)

                if func_vectors:  # اضافه‌کردن به داده‌ها
                    # پد کردن فانکشن‌ها به طول ثابت
                    padded_function = pad_sequences([func_vectors], maxlen=max_function_length, padding='post', dtype='float32')[0]
                    X.append(padded_function)
                    Y.append(label)

    X = np.array(X, dtype='float32')
    Y = np.array(Y, dtype='int32')

    # ذخیره داده‌ها
    batch_file = os.path.join(CACHE_DIR, f"batch_{len(os.listdir(CACHE_DIR))}.pkl")
    with open(batch_file, 'wb') as f:
        pickle.dump((X, Y), f)
    print(f"Batch saved to {batch_file}")



# def train_LSTM():
#     # بارگذاری داده‌ها
#     X, Y = load_batches()
#     print(f"Shape of X: {X.shape}")  # باید (samples, max_function_length, vector_length) باشد
#     print(f"Shape of Y: {Y.shape}")  # باید (samples,) باشد
#     print("Distribution in Y:", np.unique(Y, return_counts=True))
#
#     # تقسیم داده‌ها به آموزش و تست
#     X_train, X_test, Y_train, Y_test = train_test_split(X, Y, test_size=0.2, random_state=42)
#     print("Distribution in Y_test:", np.unique(Y_test, return_counts=True))
#
#     model = Sequential([
#         Conv1D(64, 3, activation='relu', input_shape=(X_train.shape[1], X_train.shape[2])),
#         Bidirectional(LSTM(128, return_sequences=True)),
#         Dropout(0.2),
#         Bidirectional(LSTM(64)),
#         Dropout(0.2),
#         Dense(1, activation='sigmoid')
#     ])
#
#     # تعریف مدل LSTM
#     # model = Sequential([
#     #     LSTM(128, input_shape=(X_train.shape[1], X_train.shape[2]), return_sequences=True),
#     #     Dropout(0.2),
#     #     LSTM(64),
#     #     Dropout(0.2),
#     #     Dense(1, activation='sigmoid')  # خروجی باینری
#     # ])
#
#     # کامپایل مدل با استفاده از Focal Loss
#     model.compile(optimizer=Adam(learning_rate=0.001),
#                   loss=focal_loss(alpha=0.25, gamma=2.0),  # استفاده از Focal Loss
#                   metrics=['accuracy'])
#
#     # آموزش مدل
#     model.fit(X_train, Y_train, epochs=10, batch_size=32, validation_split=0.1, verbose=2)
#
#     # پیش‌بینی روی داده‌های تست
#     Y_pred = (model.predict(X_test) > 0.5).astype("int32")
#
#     # محاسبه معیارها
#     accuracy = accuracy_score(Y_test, Y_pred)
#     report = classification_report(Y_test, Y_pred, target_names=['Safe', 'Vulnerable'], labels=[0, 1])
#
#     print(f"Accuracy: {accuracy}")
#     print("Classification Report:")
#     print(report)
#
#     # ذخیره مدل
#     model.save('final_model_with_focal_loss.h5')
#     print("Training complete with Focal Loss.")


def train_LSTM():
    # بارگذاری داده‌ها
    X, Y = load_batches()
    print(f"Shape of X: {X.shape}")  # باید (samples, max_function_length, vector_length) باشد
    print(f"Shape of Y: {Y.shape}")  # باید (samples,) باشد
    print("Distribution in Y:", np.unique(Y, return_counts=True))

    # تقسیم داده‌ها به آموزش و تست
    X_train, X_test, Y_train, Y_test = train_test_split(X, Y, test_size=0.2, random_state=42)
    print("Distribution in Y_test:", np.unique(Y_test, return_counts=True))

    # تعریف مدل BiGRU
    model = Sequential([
        Bidirectional(GRU(128, return_sequences=True), input_shape=(X_train.shape[1], X_train.shape[2])),
        Dropout(0.5),  # اضافه کردن Dropout برای جلوگیری از Overfitting
        Bidirectional(GRU(64)),  # یک لایه دیگر BiGRU بدون بازگشت توالی
        Dropout(0.5),  # Dropout بیشتر برای بهبود تعمیم‌پذیری
        Dense(1, activation='sigmoid')  # لایه خروجی برای دسته‌بندی باینری
    ])

    # کامپایل مدل
    model.compile(
        optimizer=Adam(learning_rate=0.001),
        loss=focal_loss(alpha=0.25, gamma=2.0),  # استفاده از Focal Loss
        metrics=['accuracy']
    )

    early_stopping = EarlyStopping(
        monitor='val_loss',  # پایش بر اساس val_loss
        patience=5,  # اگر val_loss برای 5 epoch متوالی بهبود نیافت، توقف شود
        restore_best_weights=True  # بهترین وزن‌ها را بازیابی کن
    )

    # آموزش مدل
    model.fit(
        X_train, Y_train,
        epochs=50,
        batch_size=32,
        validation_split=0.1,
        callbacks=[early_stopping],  # اضافه کردن Early Stopping
        verbose=2
    )

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
    for i in range(0, len(files), batch_size):
        batch_files = files[i:i + batch_size]
        process_batch(batch_files, target_vulner)

    train_LSTM()

# Epoch 1/50
# 15433/15433 - 657s - 43ms/step - accuracy: 0.9752 - loss: 0.0079 - val_accuracy: 0.9780 - val_loss: 0.0069
# Epoch 2/50
# 15433/15433 - 936s - 61ms/step - accuracy: 0.9779 - loss: 0.0068 - val_accuracy: 0.9780 - val_loss: 0.0065
# Epoch 3/50
# 15433/15433 - 1487s - 96ms/step - accuracy: 0.9784 - loss: 0.0063 - val_accuracy: 0.9783 - val_loss: 0.0060
# Epoch 4/50
# 15433/15433 - 1471s - 95ms/step - accuracy: 0.9787 - loss: 0.0061 - val_accuracy: 0.9788 - val_loss: 0.0058
# Epoch 5/50
# 15433/15433 - 1464s - 95ms/step - accuracy: 0.9789 - loss: 0.0059 - val_accuracy: 0.9790 - val_loss: 0.0057
# Epoch 6/50
# 15433/15433 - 1451s - 94ms/step - accuracy: 0.9790 - loss: 0.0058 - val_accuracy: 0.9791 - val_loss: 0.0056
# Epoch 7/50
# 15433/15433 - 1460s - 95ms/step - accuracy: 0.9792 - loss: 0.0057 - val_accuracy: 0.9791 - val_loss: 0.0056
# Epoch 8/50
# 15433/15433 - 1466s - 95ms/step - accuracy: 0.9792 - loss: 0.0056 - val_accuracy: 0.9794 - val_loss: 0.0055
# Epoch 9/50
# 15433/15433 - 1464s - 95ms/step - accuracy: 0.9792 - loss: 0.0055 - val_accuracy: 0.9795 - val_loss: 0.0054
# Epoch 10/50
# 15433/15433 - 1454s - 94ms/step - accuracy: 0.9791 - loss: 0.0055 - val_accuracy: 0.9789 - val_loss: 0.0055
# Epoch 11/50
# 15433/15433 - 1449s - 94ms/step - accuracy: 0.9792 - loss: 0.0055 - val_accuracy: 0.9789 - val_loss: 0.0055
# Epoch 12/50
# 15433/15433 - 1476s - 96ms/step - accuracy: 0.9793 - loss: 0.0054 - val_accuracy: 0.9795 - val_loss: 0.0054
# Epoch 13/50
# 15433/15433 - 1463s - 95ms/step - accuracy: 0.9794 - loss: 0.0054 - val_accuracy: 0.9794 - val_loss: 0.0053
# Epoch 14/50
# 15433/15433 - 1656s - 107ms/step - accuracy: 0.9794 - loss: 0.0054 - val_accuracy: 0.9793 - val_loss: 0.0054
# Epoch 15/50
# 15433/15433 - 732s - 47ms/step - accuracy: 0.9793 - loss: 0.0054 - val_accuracy: 0.9793 - val_loss: 0.0054
# Epoch 16/50
# 15433/15433 - 1466s - 95ms/step - accuracy: 0.9794 - loss: 0.0053 - val_accuracy: 0.9795 - val_loss: 0.0053
# Epoch 17/50
# 15433/15433 - 1457s - 94ms/step - accuracy: 0.9793 - loss: 0.0053 - val_accuracy: 0.9792 - val_loss: 0.0054
# Epoch 18/50
# 15433/15433 - 1456s - 94ms/step - accuracy: 0.9795 - loss: 0.0053 - val_accuracy: 0.9792 - val_loss: 0.0053
# Epoch 19/50
# 15433/15433 - 1469s - 95ms/step - accuracy: 0.9795 - loss: 0.0053 - val_accuracy: 0.9793 - val_loss: 0.0052
# Epoch 20/50
# 15433/15433 - 1439s - 93ms/step - accuracy: 0.9792 - loss: 0.0053 - val_accuracy: 0.9793 - val_loss: 0.0055
# Epoch 21/50
# 15433/15433 - 1444s - 94ms/step - accuracy: 0.9793 - loss: 0.0053 - val_accuracy: 0.9791 - val_loss: 0.0055
# Epoch 22/50
# 15433/15433 - 1470s - 95ms/step - accuracy: 0.9793 - loss: 0.0053 - val_accuracy: 0.9790 - val_loss: 0.0054
# Epoch 23/50
# 15433/15433 - 1461s - 95ms/step - accuracy: 0.9794 - loss: 0.0053 - val_accuracy: 0.9781 - val_loss: 0.0058
# Epoch 24/50
# 15433/15433 - 1450s - 94ms/step - accuracy: 0.9793 - loss: 0.0053 - val_accuracy: 0.9794 - val_loss: 0.0054
# 4287/4287 ━━━━━━━━━━━━━━━━━━━━ 131s 30ms/step
# WARNING:absl:You are saving your model as an HDF5 file via `model.save()` or `keras.saving.save_model(model)`. This file format is considered legacy. We recommend using instead the native Keras format, e.g. `model.save('my_model.keras')` or `keras.saving.save_model(model, 'my_model.keras')`.
# Accuracy: 0.9808934377232501
# Classification Report:
#               precision    recall  f1-score   support
#
#         Safe       0.98      1.00      0.99    133441
#   Vulnerable       0.88      0.34      0.50      3737
#
#     accuracy                           0.98    137178
#    macro avg       0.93      0.67      0.74    137178
# weighted avg       0.98      0.98      0.98    137178

