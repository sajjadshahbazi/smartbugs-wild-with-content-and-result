import json
import re
import os
from pathlib import Path
from imblearn.over_sampling import SMOTE
import pandas as pd
from keras.src.layers import GlobalAveragePooling2D
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.utils import Sequence
import sys
from gensim.models import Word2Vec
import numpy as np
import pickle
import PreProcessTools
import numpy as np
import io
import seaborn as sns
from tensorflow.keras import backend as K
from sklearn.model_selection import train_test_split
from tensorflow.keras.models import Sequential
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix, roc_auc_score
from tensorflow.keras.layers import Conv2D, Conv1D, Attention, LeakyReLU, UpSampling1D, Concatenate, Dropout, ZeroPadding1D, GlobalAveragePooling1D, Activation, Bidirectional, concatenate, Cropping2D, MaxPooling2D, MaxPooling1D, UpSampling2D, concatenate, Flatten, Dense, Bidirectional, LSTM, Input, Reshape, BatchNormalization, Reshape
from tensorflow.keras.models import Model
from tensorflow.keras import layers, models
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau
import matplotlib.pyplot as plt

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

# ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), '..'))
# CACHE_DIR = os.path.join(ROOT, 'vectorcollections')

ROOT = '/content/smartbugs-wild-with-content-and-result' # Linux
CACHE_DIR = os.path.join(ROOT, 'vectorcollections') # Linux

cache_path = os.path.join(CACHE_DIR, 'tokenized_fragments.pkl')
vulnerability_fd = open(os.path.join(ROOT, 'metadata', 'vulnerabilities.csv'), 'w', encoding='utf-8')

# PATH = f"{ROOT}\\contracts\\"  # main data set
# PATH = f"{ROOT}\\contract\\"  # part of main data set
# PATH = f"{ROOT}\\contra\\"  # one smart contract

PATH = os.path.join(ROOT, 'contracts') # linux
os.chdir(PATH)

final_df = pd.DataFrame(columns=['X', 'Y'])



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
        path_result = os.path.join(f"{ROOT}results", tool, output_name, contract_name, 'result.json') # Linux
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


def load_batches(folder, file_extension=".pkl"):
    X_batches, Y_batches = [], []
    for file in os.listdir(folder):
        if file.endswith(file_extension):
            with open(os.path.join(folder, file), 'rb') as f:
                X, Y = pickle.load(f)
                X_batches.append(X)
                Y_batches.append(Y)
    return np.vstack(X_batches), np.hstack(Y_batches)


# بارگذاری داده‌ها
X, Y = load_batches(CACHE_DIR, file_extension=".pkl")
print(f"Shape of X: {X.shape}")
print(f"Shape of Y: {Y.shape}")
print("Distribution in Y:", np.unique(Y, return_counts=True))

def train_LSTM_UNET_improved():
    # بارگذاری داده‌ها (بدون تغییر)
    X, Y = load_batches(CACHE_DIR, file_extension=".pkl")
    print(f"Shape of X: {X.shape}")
    print(f"Shape of Y: {Y.shape}")
    print("Distribution in Y:", np.unique(Y, return_counts=True))

    # تقسیم داده‌ها به مجموعه آموزشی و تست (بدون تغییر)
    X_train_full, X_test, Y_train_full, Y_test = train_test_split(X, Y, test_size=0.2, random_state=42)
    print("Distribution in Y_test:", np.unique(Y_test, return_counts=True))

    # تعریف ورودی (بدون تغییر)
    inputs = Input(shape=(X_train_full.shape[1], X_train_full.shape[2]))

    # شاخه U-Net بهبودیافته
    padded = ZeroPadding1D(padding=(7,7))(inputs)  # Padding برای تطابق ابعاد

    # Encoder با 4 سطح
    conv1 = Conv1D(64, 3, padding='same')(padded)
    conv1 = BatchNormalization()(conv1)
    conv1 = LeakyReLU(alpha=0.1)(conv1)
    conv1 = Conv1D(64, 3, padding='same')(conv1)
    conv1 = BatchNormalization()(conv1)
    conv1 = LeakyReLU(alpha=0.1)(conv1)
    pool1 = MaxPooling1D(2)(conv1)  # 64 -> 32

    conv2 = Conv1D(128, 3, padding='same')(pool1)
    conv2 = BatchNormalization()(conv2)
    conv2 = LeakyReLU(alpha=0.1)(conv2)
    conv2 = Conv1D(128, 3, padding='same')(conv2)
    conv2 = BatchNormalization()(conv2)
    conv2 = LeakyReLU(alpha=0.1)(conv2)
    pool2 = MaxPooling1D(2)(conv2)  # 32 -> 16

    conv3 = Conv1D(256, 3, padding='same')(pool2)
    conv3 = BatchNormalization()(conv3)
    conv3 = LeakyReLU(alpha=0.1)(conv3)
    conv3 = Conv1D(256, 3, padding='same')(conv3)
    conv3 = BatchNormalization()(conv3)
    conv3 = LeakyReLU(alpha=0.1)(conv3)
    pool3 = MaxPooling1D(2)(conv3)  # 16 -> 8

    conv4 = Conv1D(512, 3, padding='same')(pool3)
    conv4 = BatchNormalization()(conv4)
    conv4 = LeakyReLU(alpha=0.1)(conv4)
    conv4 = Conv1D(512, 3, padding='same')(conv4)
    conv4 = BatchNormalization()(conv4)
    conv4 = LeakyReLU(alpha=0.1)(conv4)
    pool4 = MaxPooling1D(2)(conv4)  # 8 -> 4

    # Bottleneck
    conv5 = Conv1D(1024, 3, padding='same')(pool4)
    conv5 = BatchNormalization()(conv5)
    conv5 = LeakyReLU(alpha=0.1)(conv5)
    conv5 = Conv1D(1024, 3, padding='same')(conv5)
    conv5 = BatchNormalization()(conv5)
    conv5 = LeakyReLU(alpha=0.1)(conv5)

    # Decoder با 4 سطح
    up6 = UpSampling1D(2)(conv5)  # 4 -> 8
    concat6 = Concatenate()([up6, conv4])
    conv6 = Conv1D(512, 3, padding='same')(concat6)
    conv6 = BatchNormalization()(conv6)
    conv6 = LeakyReLU(alpha=0.1)(conv6)
    conv6 = Conv1D(512, 3, padding='same')(conv6)
    conv6 = BatchNormalization()(conv6)
    conv6 = LeakyReLU(alpha=0.1)(conv6)

    up7 = UpSampling1D(2)(conv6)  # 8 -> 16
    concat7 = Concatenate()([up7, conv3])
    conv7 = Conv1D(256, 3, padding='same')(concat7)
    conv7 = BatchNormalization()(conv7)
    conv7 = LeakyReLU(alpha=0.1)(conv7)
    conv7 = Conv1D(256, 3, padding='same')(conv7)
    conv7 = BatchNormalization()(conv7)
    conv7 = LeakyReLU(alpha=0.1)(conv7)

    up8 = UpSampling1D(2)(conv7)  # 16 -> 32
    concat8 = Concatenate()([up8, conv2])
    conv8 = Conv1D(128, 3, padding='same')(concat8)
    conv8 = BatchNormalization()(conv8)
    conv8 = LeakyReLU(alpha=0.1)(conv8)
    conv8 = Conv1D(128, 3, padding='same')(conv8)
    conv8 = BatchNormalization()(conv8)
    conv8 = LeakyReLU(alpha=0.1)(conv8)

    up9 = UpSampling1D(2)(conv8)  # 32 -> 64
    concat9 = Concatenate()([up9, conv1])
    conv9 = Conv1D(64, 3, padding='same')(concat9)
    conv9 = BatchNormalization()(conv9)
    conv9 = LeakyReLU(alpha=0.1)(conv9)
    conv9 = Conv1D(64, 3, padding='same')(conv9)
    conv9 = BatchNormalization()(conv9)
    conv9 = LeakyReLU(alpha=0.1)(conv9)

    # تبدیل خروجی U-Net به بردار ثابت‌اندازه
    conv10 = Conv1D(128, 1)(conv9)  # (64, 128)
    unet_output = GlobalAveragePooling1D()(conv10)  # (128,)

    # شاخه LSTM (بدون تغییر)
    lstm1 = Bidirectional(LSTM(128, return_sequences=True))(inputs)
    lstm2 = Bidirectional(LSTM(64))(lstm1)  # (128,)

    # ترکیب خروجی‌ها با Attention
    unet_output_reshaped = Reshape((1, 128))(unet_output)  # (1, 128)
    lstm_output_reshaped = Reshape((1, 128))(lstm2)  # (1, 128)
    combined = Attention()([unet_output_reshaped, lstm_output_reshaped])  # (1, 128)
    combined = Flatten()(combined)  # (128,)

    # لایه‌های Dense بیشتر
    dense1 = Dense(256, activation='relu')(combined)
    dense2 = Dense(128, activation='relu')(dense1)

    # لایه خروجی
    output = Dense(1, activation='sigmoid')(dense2)

    # ساخت مدل
    model = Model(inputs=inputs, outputs=output)

    # کامپایل مدل
    model.compile(
        optimizer=Adam(learning_rate=0.001),
        loss="binary_crossentropy",
        metrics=['accuracy']
    )

    # EarlyStopping و ReduceLROnPlateau
    early_stopping = EarlyStopping(monitor='val_loss', patience=10, restore_best_weights=True)
    reduce_lr = ReduceLROnPlateau(monitor='val_loss', factor=0.2, patience=5, min_lr=0.0001)

    # آموزش مدل
    history = model.fit(
        X_train_full,
        Y_train_full,
        epochs=50,
        batch_size=64,  # افزایش batch size
        validation_split=0.2,
        callbacks=[early_stopping, reduce_lr],
        verbose=2
    )

    # ارزیابی روی مجموعه تست
    test_loss, test_accuracy = model.evaluate(X_test, Y_test, verbose=0)
    print(f"Test Loss: {test_loss:.4f}")
    print(f"Test Accuracy: {test_accuracy:.4f}")

    # ذخیره مدل
    model.save('final_LSTM_UNET_improved.keras')
    print("Training complete with improved LSTM and U-Net.")

if __name__ == "__main__":
    train_LSTM_UNET_improved()


# Epoch 4/50
# 606/606 - 24s - 40ms/step - accuracy: 0.7927 - loss: 0.4177 - val_accuracy: 0.7900 - val_loss: 0.4202 - learning_rate: 0.0010
# Epoch 5/50
# 606/606 - 24s - 40ms/step - accuracy: 0.8005 - loss: 0.4018 - val_accuracy: 0.7941 - val_loss: 0.4127 - learning_rate: 0.0010
# Epoch 6/50
# 606/606 - 24s - 40ms/step - accuracy: 0.8090 - loss: 0.3891 - val_accuracy: 0.8052 - val_loss: 0.4045 - learning_rate: 0.0010
# Epoch 7/50
# 606/606 - 24s - 40ms/step - accuracy: 0.8149 - loss: 0.3807 - val_accuracy: 0.8057 - val_loss: 0.3943 - learning_rate: 0.0010
# Epoch 8/50
# 606/606 - 24s - 40ms/step - accuracy: 0.8198 - loss: 0.3709 - val_accuracy: 0.8032 - val_loss: 0.3862 - learning_rate: 0.0010
# Epoch 9/50
# 606/606 - 25s - 40ms/step - accuracy: 0.8256 - loss: 0.3629 - val_accuracy: 0.8141 - val_loss: 0.3802 - learning_rate: 0.0010
# Epoch 10/50
# 606/606 - 24s - 40ms/step - accuracy: 0.8310 - loss: 0.3565 - val_accuracy: 0.8229 - val_loss: 0.3682 - learning_rate: 0.0010
# Epoch 11/50
# 606/606 - 25s - 41ms/step - accuracy: 0.8363 - loss: 0.3471 - val_accuracy: 0.8200 - val_loss: 0.3656 - learning_rate: 0.0010
# Epoch 12/50
# 606/606 - 25s - 41ms/step - accuracy: 0.8406 - loss: 0.3388 - val_accuracy: 0.8277 - val_loss: 0.3587 - learning_rate: 0.0010
# Epoch 13/50
# 606/606 - 24s - 40ms/step - accuracy: 0.8452 - loss: 0.3336 - val_accuracy: 0.8284 - val_loss: 0.3551 - learning_rate: 0.0010
# Epoch 14/50
# 606/606 - 24s - 40ms/step - accuracy: 0.8500 - loss: 0.3248 - val_accuracy: 0.8272 - val_loss: 0.3620 - learning_rate: 0.0010
# Epoch 15/50
# 606/606 - 24s - 40ms/step - accuracy: 0.8543 - loss: 0.3188 - val_accuracy: 0.8355 - val_loss: 0.3518 - learning_rate: 0.0010
# Epoch 16/50
# 606/606 - 24s - 40ms/step - accuracy: 0.8565 - loss: 0.3115 - val_accuracy: 0.8398 - val_loss: 0.3550 - learning_rate: 0.0010
# Epoch 17/50
# 606/606 - 24s - 40ms/step - accuracy: 0.8597 - loss: 0.3067 - val_accuracy: 0.8394 - val_loss: 0.3522 - learning_rate: 0.0010
# Epoch 18/50
# 606/606 - 24s - 40ms/step - accuracy: 0.8643 - loss: 0.3001 - val_accuracy: 0.8413 - val_loss: 0.3437 - learning_rate: 0.0010
# Epoch 19/50
# 606/606 - 24s - 40ms/step - accuracy: 0.8692 - loss: 0.2921 - val_accuracy: 0.8383 - val_loss: 0.3514 - learning_rate: 0.0010
# Epoch 20/50
# 606/606 - 24s - 40ms/step - accuracy: 0.8732 - loss: 0.2856 - val_accuracy: 0.8442 - val_loss: 0.3455 - learning_rate: 0.0010
# Epoch 21/50
# 606/606 - 25s - 41ms/step - accuracy: 0.8768 - loss: 0.2787 - val_accuracy: 0.8453 - val_loss: 0.3542 - learning_rate: 0.0010
# Epoch 22/50
# 606/606 - 25s - 42ms/step - accuracy: 0.8826 - loss: 0.2721 - val_accuracy: 0.8469 - val_loss: 0.3452 - learning_rate: 0.0010
# Epoch 23/50
# 606/606 - 26s - 43ms/step - accuracy: 0.8850 - loss: 0.2646 - val_accuracy: 0.8485 - val_loss: 0.3412 - learning_rate: 0.0010
# Epoch 24/50
# 606/606 - 25s - 41ms/step - accuracy: 0.8871 - loss: 0.2598 - val_accuracy: 0.8533 - val_loss: 0.3518 - learning_rate: 0.0010
# Epoch 25/50
# 606/606 - 25s - 42ms/step - accuracy: 0.8923 - loss: 0.2539 - val_accuracy: 0.8534 - val_loss: 0.3495 - learning_rate: 0.0010
# Epoch 26/50
# 606/606 - 25s - 41ms/step - accuracy: 0.8960 - loss: 0.2462 - val_accuracy: 0.8604 - val_loss: 0.3420 - learning_rate: 0.0010
# Epoch 27/50
# 606/606 - 25s - 41ms/step - accuracy: 0.8972 - loss: 0.2425 - val_accuracy: 0.8502 - val_loss: 0.3543 - learning_rate: 0.0010
# Epoch 28/50
# 606/606 - 25s - 41ms/step - accuracy: 0.9012 - loss: 0.2371 - val_accuracy: 0.8544 - val_loss: 0.3529 - learning_rate: 0.0010
# Epoch 29/50
# 606/606 - 25s - 41ms/step - accuracy: 0.9189 - loss: 0.2018 - val_accuracy: 0.8644 - val_loss: 0.3421 - learning_rate: 2.0000e-04
# Epoch 30/50
# 606/606 - 25s - 41ms/step - accuracy: 0.9244 - loss: 0.1919 - val_accuracy: 0.8631 - val_loss: 0.3478 - learning_rate: 2.0000e-04
# Epoch 31/50
# 606/606 - 25s - 41ms/step - accuracy: 0.9257 - loss: 0.1880 - val_accuracy: 0.8644 - val_loss: 0.3532 - learning_rate: 2.0000e-04
# Epoch 32/50
# 606/606 - 25s - 41ms/step - accuracy: 0.9258 - loss: 0.1847 - val_accuracy: 0.8668 - val_loss: 0.3546 - learning_rate: 2.0000e-04
# Epoch 33/50
# 606/606 - 25s - 41ms/step - accuracy: 0.9274 - loss: 0.1812 - val_accuracy: 0.8666 - val_loss: 0.3630 - learning_rate: 2.0000e-04
# Test Loss: 0.3296
# Test Accuracy: 0.8521
# Training complete with improved LSTM and U-Net.

