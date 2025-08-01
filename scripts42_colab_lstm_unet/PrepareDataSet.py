import json
import re
import os
from pathlib import Path
from imblearn.over_sampling import SMOTE
import pandas as pd
from keras.src.layers import GlobalAveragePooling2D, MultiHeadAttention
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
from tensorflow.keras.layers import Conv2D, Add, Conv1D, ZeroPadding2D, Attention, LeakyReLU, UpSampling1D, Concatenate, Dropout, ZeroPadding1D, GlobalAveragePooling1D, Activation, Bidirectional, concatenate, Cropping2D, MaxPooling2D, MaxPooling1D, UpSampling2D, concatenate, Flatten, Dense, Bidirectional, LSTM, Input, Reshape, BatchNormalization, Reshape
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
    # بارگذاری داده‌ها
    X, Y = load_batches(CACHE_DIR, file_extension=".pkl")
    X_train_full, X_test, Y_train_full, Y_test = train_test_split(X, Y, test_size=0.2, random_state=42)

    # تعریف مدل
    inputs = Input(shape=(X_train_full.shape[1], X_train_full.shape[2]))

    # شاخه LSTM
    lstm1 = Bidirectional(LSTM(128, return_sequences=True))(inputs)
    lstm2 = Bidirectional(LSTM(64))(lstm1)

    # شاخه U-Net
    # Encoder
    conv1 = Conv1D(128, 3, padding='same')(inputs)  # (None, 50, 128)
    conv1 = BatchNormalization()(conv1)
    conv1 = LeakyReLU(negative_slope=0.1)(conv1)
    conv1_residual = conv1
    conv1 = Conv1D(128, 3, padding='same')(conv1)
    conv1 = BatchNormalization()(conv1)
    conv1 = LeakyReLU(negative_slope=0.1)(conv1)
    conv1 = Add()([conv1, conv1_residual])
    pool1 = MaxPooling1D(2)(conv1)  # (None, 25, 128)

    conv2 = Conv1D(256, 3, padding='same')(pool1)  # (None, 25, 256)
    conv2 = BatchNormalization()(conv2)
    conv2 = LeakyReLU(negative_slope=0.1)(conv2)
    conv2_residual = conv2
    conv2 = Conv1D(256, 3, padding='same')(conv2)
    conv2 = BatchNormalization()(conv2)
    conv2 = LeakyReLU(negative_slope=0.1)(conv2)
    conv2 = Add()([conv2, conv2_residual])
    pool2 = MaxPooling1D(2)(conv2)  # (None, 12, 256)

    conv3 = Conv1D(512, 3, padding='same')(pool2)  # (None, 12, 512)
    conv3 = BatchNormalization()(conv3)
    conv3 = LeakyReLU(negative_slope=0.1)(conv3)
    conv3_residual = conv3
    conv3 = Conv1D(512, 3, padding='same')(conv3)
    conv3 = BatchNormalization()(conv3)
    conv3 = LeakyReLU(negative_slope=0.1)(conv3)
    conv3 = Add()([conv3, conv3_residual])
    pool3 = MaxPooling1D(2)(conv3)  # (None, 6, 512)

    conv4 = Conv1D(1024, 3, padding='same')(pool3)  # (None, 6, 1024)
    conv4 = BatchNormalization()(conv4)
    conv4 = LeakyReLU(negative_slope=0.1)(conv4)
    conv4_residual = conv4
    conv4 = Conv1D(1024, 3, padding='same')(conv4)
    conv4 = BatchNormalization()(conv4)
    conv4 = LeakyReLU(negative_slope=0.1)(conv4)
    conv4 = Add()([conv4, conv4_residual])
    pool4 = MaxPooling1D(2)(conv4)  # (None, 3, 1024)

    conv5 = Conv1D(2048, 3, padding='same')(pool4)  # (None, 3, 2048)
    conv5 = BatchNormalization()(conv5)
    conv5 = LeakyReLU(negative_slope=0.1)(conv5)
    conv5_residual = conv5
    conv5 = Conv1D(2048, 3, padding='same')(conv5)
    conv5 = BatchNormalization()(conv5)
    conv5 = LeakyReLU(negative_slope=0.1)(conv5)
    conv5 = Add()([conv5, conv5_residual])

    # Decoder
    up6 = UpSampling1D(2)(conv5)  # (None, 6, 2048)
    up6 = ZeroPadding1D(padding=(0, 0))(up6)  # تطابق با conv4 (6, 1024)
    concat6 = Concatenate()([up6, conv4])
    conv6 = Conv1D(1024, 3, padding='same')(concat6)
    conv6 = BatchNormalization()(conv6)
    conv6 = LeakyReLU(negative_slope=0.1)(conv6)

    up7 = UpSampling1D(2)(conv6)  # (None, 12, 1024)
    up7 = ZeroPadding1D(padding=(0, 0))(up7)  # تطابق با conv3 (12, 512)
    concat7 = Concatenate()([up7, conv3])
    conv7 = Conv1D(512, 3, padding='same')(concat7)
    conv7 = BatchNormalization()(conv7)
    conv7 = LeakyReLU(negative_slope=0.1)(conv7)

    up8 = UpSampling1D(2)(conv7)  # (None, 24, 512)
    up8 = ZeroPadding1D(padding=(0, 1))(up8)  # تطابق با conv2 (25, 256)
    concat8 = Concatenate()([up8, conv2])
    conv8 = Conv1D(256, 3, padding='same')(concat8)
    conv8 = BatchNormalization()(conv8)
    conv8 = LeakyReLU(negative_slope=0.1)(conv8)

    up9 = UpSampling1D(2)(conv8)  # (None, 50, 256)
    up9 = ZeroPadding1D(padding=(0, 0))(up9)  # تطابق با conv1 (50, 128)
    concat9 = Concatenate()([up9, conv1])
    conv9 = Conv1D(128, 3, padding='same')(concat9)
    conv9 = BatchNormalization()(conv9)
    conv9 = LeakyReLU(negative_slope=0.1)(conv9)

    unet_output = GlobalAveragePooling1D()(conv9)

    # ترکیب با Cross-Attention
    unet_output_reshaped = Reshape((1, 128))(unet_output)
    lstm_output_reshaped = Reshape((1, 128))(lstm2)
    combined = MultiHeadAttention(num_heads=8, key_dim=128)(query=lstm_output_reshaped, value=unet_output_reshaped, key=unet_output_reshaped)
    combined = Flatten()(combined)

    # لایه‌های Dense
    dense1 = Dense(256, activation='relu')(combined)
    dense1 = Dropout(0.4)(dense1)
    dense2 = Dense(128, activation='relu')(dense1)
    dense2 = Dropout(0.4)(dense2)
    output = Dense(1, activation='sigmoid')(dense2)

    # ساخت مدل
    model = Model(inputs=inputs, outputs=output)
    model.compile(optimizer=Adam(learning_rate=0.001), loss='binary_crossentropy', metrics=['accuracy'])

    # تنظیمات callbacks
    early_stopping = EarlyStopping(monitor='val_accuracy', patience=10, restore_best_weights=True, mode='max')
    reduce_lr = ReduceLROnPlateau(monitor='val_accuracy', factor=0.2, patience=5, min_lr=0.0001, mode='max')

    # آموزش مدل
    history = model.fit(X_train_full, Y_train_full, epochs=100, batch_size=128, validation_split=0.2,
                        callbacks=[early_stopping, reduce_lr], verbose=2)

    # ذخیره و نمایش گراف
    docs_dir = os.path.join(ROOT, 'doc')
    os.makedirs(docs_dir, exist_ok=True)
    plt.figure(figsize=(10, 6))
    plt.plot(history.history['accuracy'], label='train_acc', color='blue')
    plt.plot(history.history['val_accuracy'], label='val_acc', color='yellow')
    plt.plot(history.history['loss'], label='train_loss', color='red')
    plt.plot(history.history['val_loss'], label='val_loss', color='green')
    plt.title('Model Accuracy and Loss')
    plt.xlabel('Epochs')
    plt.ylabel('Accuracy / Loss')
    plt.legend(loc='best')
    plt.grid()
    output_image_path = os.path.join(docs_dir, 'training_plot_lstm_unet_improved.png')
    plt.savefig(output_image_path, dpi=300, bbox_inches='tight')
    plt.show()

    # ارزیابی مدل
    Y_pred = (model.predict(X_test) > 0.5).astype("int32")
    accuracy = accuracy_score(Y_test, Y_pred)
    report = classification_report(Y_test, Y_pred, target_names=['Safe', 'Vulnerable'], labels=[0, 1])

    print(f"Accuracy: {accuracy}")
    print("Classification Report:")
    print(report)


if __name__ == "__main__":
    train_LSTM_UNET_improved()



# Epoch 5/100
# 303/303 - 13s - 44ms/step - accuracy: 0.8613 - loss: 0.3116 - val_accuracy: 0.8309 - val_loss: 0.4019 - learning_rate: 0.0010
# Epoch 6/100
# 303/303 - 13s - 44ms/step - accuracy: 0.8693 - loss: 0.2974 - val_accuracy: 0.8453 - val_loss: 0.3363 - learning_rate: 0.0010
# Epoch 7/100
# 303/303 - 13s - 44ms/step - accuracy: 0.8771 - loss: 0.2801 - val_accuracy: 0.8489 - val_loss: 0.3566 - learning_rate: 0.0010
# Epoch 8/100
# 303/303 - 13s - 44ms/step - accuracy: 0.8824 - loss: 0.2702 - val_accuracy: 0.8214 - val_loss: 0.3971 - learning_rate: 0.0010
# Epoch 9/100
# 303/303 - 13s - 44ms/step - accuracy: 0.8914 - loss: 0.2576 - val_accuracy: 0.8550 - val_loss: 0.3545 - learning_rate: 0.0010
# Epoch 10/100
# 303/303 - 13s - 44ms/step - accuracy: 0.8946 - loss: 0.2478 - val_accuracy: 0.8559 - val_loss: 0.3432 - learning_rate: 0.0010
# Epoch 11/100
# 303/303 - 13s - 43ms/step - accuracy: 0.9011 - loss: 0.2368 - val_accuracy: 0.8527 - val_loss: 0.4003 - learning_rate: 0.0010
# Epoch 12/100
# 303/303 - 13s - 44ms/step - accuracy: 0.9039 - loss: 0.2275 - val_accuracy: 0.8603 - val_loss: 0.3498 - learning_rate: 0.0010
# Epoch 13/100
# 303/303 - 13s - 44ms/step - accuracy: 0.9069 - loss: 0.2231 - val_accuracy: 0.8643 - val_loss: 0.3454 - learning_rate: 0.0010
# Epoch 14/100
# 303/303 - 13s - 44ms/step - accuracy: 0.9087 - loss: 0.2186 - val_accuracy: 0.8562 - val_loss: 0.3796 - learning_rate: 0.0010
# Epoch 15/100
# 303/303 - 13s - 43ms/step - accuracy: 0.9114 - loss: 0.2130 - val_accuracy: 0.8634 - val_loss: 0.3822 - learning_rate: 0.0010
# Epoch 16/100
# 303/303 - 13s - 43ms/step - accuracy: 0.9153 - loss: 0.2044 - val_accuracy: 0.8602 - val_loss: 0.3896 - learning_rate: 0.0010
# Epoch 17/100
# 303/303 - 13s - 44ms/step - accuracy: 0.9171 - loss: 0.2017 - val_accuracy: 0.8670 - val_loss: 0.4393 - learning_rate: 0.0010
# Epoch 18/100
# 303/303 - 13s - 44ms/step - accuracy: 0.9187 - loss: 0.1971 - val_accuracy: 0.8655 - val_loss: 0.4221 - learning_rate: 0.0010
# Epoch 19/100
# 303/303 - 13s - 44ms/step - accuracy: 0.9204 - loss: 0.1927 - val_accuracy: 0.8673 - val_loss: 0.4305 - learning_rate: 0.0010
# Epoch 20/100
# 303/303 - 13s - 43ms/step - accuracy: 0.9239 - loss: 0.1861 - val_accuracy: 0.8590 - val_loss: 0.4816 - learning_rate: 0.0010
# Epoch 21/100
# 303/303 - 13s - 43ms/step - accuracy: 0.9231 - loss: 0.1874 - val_accuracy: 0.8589 - val_loss: 0.5546 - learning_rate: 0.0010
# Epoch 22/100
# 303/303 - 13s - 44ms/step - accuracy: 0.9245 - loss: 0.1831 - val_accuracy: 0.8651 - val_loss: 0.3878 - learning_rate: 0.0010
# Epoch 23/100
# 303/303 - 13s - 44ms/step - accuracy: 0.9277 - loss: 0.1784 - val_accuracy: 0.8658 - val_loss: 0.4996 - learning_rate: 0.0010
# Epoch 24/100
# 303/303 - 13s - 43ms/step - accuracy: 0.9262 - loss: 0.1802 - val_accuracy: 0.8566 - val_loss: 0.4249 - learning_rate: 0.0010
# Epoch 25/100
# 303/303 - 13s - 44ms/step - accuracy: 0.9344 - loss: 0.1593 - val_accuracy: 0.8724 - val_loss: 0.4382 - learning_rate: 2.0000e-04
# Epoch 26/100
# 303/303 - 13s - 44ms/step - accuracy: 0.9386 - loss: 0.1472 - val_accuracy: 0.8726 - val_loss: 0.4618 - learning_rate: 2.0000e-04
# Epoch 27/100
# 303/303 - 13s - 44ms/step - accuracy: 0.9395 - loss: 0.1448 - val_accuracy: 0.8732 - val_loss: 0.4834 - learning_rate: 2.0000e-04
# Epoch 28/100
# 303/303 - 13s - 44ms/step - accuracy: 0.9393 - loss: 0.1436 - val_accuracy: 0.8689 - val_loss: 0.5595 - learning_rate: 2.0000e-04
# Epoch 29/100
# 303/303 - 13s - 44ms/step - accuracy: 0.9401 - loss: 0.1423 - val_accuracy: 0.8705 - val_loss: 0.6204 - learning_rate: 2.0000e-04
# Epoch 30/100
# 303/303 - 13s - 44ms/step - accuracy: 0.9409 - loss: 0.1418 - val_accuracy: 0.8729 - val_loss: 0.5137 - learning_rate: 2.0000e-04
# Epoch 31/100
# 303/303 - 13s - 43ms/step - accuracy: 0.9408 - loss: 0.1417 - val_accuracy: 0.8725 - val_loss: 0.5669 - learning_rate: 2.0000e-04
# Epoch 32/100
# 303/303 - 13s - 44ms/step - accuracy: 0.9414 - loss: 0.1400 - val_accuracy: 0.8733 - val_loss: 0.6386 - learning_rate: 2.0000e-04
# Epoch 33/100
# 303/303 - 13s - 43ms/step - accuracy: 0.9416 - loss: 0.1395 - val_accuracy: 0.8726 - val_loss: 0.5951 - learning_rate: 2.0000e-04
# Epoch 34/100
# 303/303 - 13s - 44ms/step - accuracy: 0.9409 - loss: 0.1400 - val_accuracy: 0.8740 - val_loss: 0.6231 - learning_rate: 2.0000e-04
# Epoch 35/100
# 303/303 - 13s - 43ms/step - accuracy: 0.9419 - loss: 0.1372 - val_accuracy: 0.8717 - val_loss: 0.6807 - learning_rate: 2.0000e-04
# Epoch 36/100
# 303/303 - 13s - 43ms/step - accuracy: 0.9416 - loss: 0.1378 - val_accuracy: 0.8728 - val_loss: 0.5985 - learning_rate: 2.0000e-04
# Epoch 37/100
# 303/303 - 13s - 44ms/step - accuracy: 0.9426 - loss: 0.1368 - val_accuracy: 0.8744 - val_loss: 0.6065 - learning_rate: 2.0000e-04
# Epoch 38/100
# 303/303 - 13s - 44ms/step - accuracy: 0.9415 - loss: 0.1376 - val_accuracy: 0.8737 - val_loss: 0.6392 - learning_rate: 2.0000e-04
# Epoch 39/100
# 303/303 - 13s - 44ms/step - accuracy: 0.9416 - loss: 0.1391 - val_accuracy: 0.8733 - val_loss: 0.6048 - learning_rate: 2.0000e-04
# Epoch 40/100
# 303/303 - 13s - 44ms/step - accuracy: 0.9417 - loss: 0.1376 - val_accuracy: 0.8745 - val_loss: 0.6375 - learning_rate: 2.0000e-04
# Epoch 41/100
# 303/303 - 13s - 44ms/step - accuracy: 0.9429 - loss: 0.1347 - val_accuracy: 0.8745 - val_loss: 0.5738 - learning_rate: 2.0000e-04
# Epoch 42/100
# 303/303 - 13s - 44ms/step - accuracy: 0.9432 - loss: 0.1339 - val_accuracy: 0.8751 - val_loss: 0.6816 - learning_rate: 2.0000e-04
# Epoch 43/100
# 303/303 - 13s - 44ms/step - accuracy: 0.9432 - loss: 0.1345 - val_accuracy: 0.8736 - val_loss: 0.6950 - learning_rate: 2.0000e-04
# Epoch 44/100
# 303/303 - 13s - 43ms/step - accuracy: 0.9426 - loss: 0.1354 - val_accuracy: 0.8751 - val_loss: 0.5907 - learning_rate: 2.0000e-04
# Epoch 45/100
# 303/303 - 13s - 43ms/step - accuracy: 0.9431 - loss: 0.1345 - val_accuracy: 0.8728 - val_loss: 0.6743 - learning_rate: 2.0000e-04
# Epoch 46/100
# 303/303 - 13s - 44ms/step - accuracy: 0.9438 - loss: 0.1340 - val_accuracy: 0.8733 - val_loss: 0.6389 - learning_rate: 2.0000e-04
# Epoch 47/100
# 303/303 - 13s - 43ms/step - accuracy: 0.9441 - loss: 0.1336 - val_accuracy: 0.8737 - val_loss: 0.6697 - learning_rate: 2.0000e-04
# Epoch 48/100
# 303/303 - 13s - 44ms/step - accuracy: 0.9443 - loss: 0.1307 - val_accuracy: 0.8759 - val_loss: 0.6800 - learning_rate: 1.0000e-04
# Epoch 49/100
# 303/303 - 13s - 44ms/step - accuracy: 0.9446 - loss: 0.1297 - val_accuracy: 0.8755 - val_loss: 0.7402 - learning_rate: 1.0000e-04
# Epoch 50/100
# 303/303 - 13s - 44ms/step - accuracy: 0.9448 - loss: 0.1296 - val_accuracy: 0.8763 - val_loss: 0.7094 - learning_rate: 1.0000e-04
# Epoch 51/100
# 303/303 - 13s - 43ms/step - accuracy: 0.9447 - loss: 0.1294 - val_accuracy: 0.8756 - val_loss: 0.6933 - learning_rate: 1.0000e-04
# Epoch 52/100
# 303/303 - 13s - 44ms/step - accuracy: 0.9443 - loss: 0.1298 - val_accuracy: 0.8755 - val_loss: 0.7277 - learning_rate: 1.0000e-04
# Epoch 53/100
# 303/303 - 13s - 43ms/step - accuracy: 0.9446 - loss: 0.1304 - val_accuracy: 0.8748 - val_loss: 0.7401 - learning_rate: 1.0000e-04
# Epoch 54/100
# 303/303 - 13s - 43ms/step - accuracy: 0.9451 - loss: 0.1298 - val_accuracy: 0.8752 - val_loss: 0.7699 - learning_rate: 1.0000e-04
# Epoch 55/100
# 303/303 - 13s - 43ms/step - accuracy: 0.9448 - loss: 0.1294 - val_accuracy: 0.8752 - val_loss: 0.7756 - learning_rate: 1.0000e-04
# Epoch 56/100
# 303/303 - 13s - 43ms/step - accuracy: 0.9445 - loss: 0.1300 - val_accuracy: 0.8755 - val_loss: 0.7437 - learning_rate: 1.0000e-04
# Epoch 57/100
# 303/303 - 13s - 44ms/step - accuracy: 0.9450 - loss: 0.1293 - val_accuracy: 0.8767 - val_loss: 0.7272 - learning_rate: 1.0000e-04
# Epoch 58/100
# 303/303 - 13s - 44ms/step - accuracy: 0.9446 - loss: 0.1301 - val_accuracy: 0.8765 - val_loss: 0.7099 - learning_rate: 1.0000e-04
# Epoch 59/100
# 303/303 - 13s - 44ms/step - accuracy: 0.9450 - loss: 0.1283 - val_accuracy: 0.8762 - val_loss: 0.7698 - learning_rate: 1.0000e-04
# Epoch 60/100
# 303/303 - 13s - 43ms/step - accuracy: 0.9449 - loss: 0.1291 - val_accuracy: 0.8764 - val_loss: 0.7201 - learning_rate: 1.0000e-04
# Epoch 61/100
# 303/303 - 13s - 44ms/step - accuracy: 0.9444 - loss: 0.1291 - val_accuracy: 0.8762 - val_loss: 0.7535 - learning_rate: 1.0000e-04
# Epoch 62/100
# 303/303 - 13s - 43ms/step - accuracy: 0.9450 - loss: 0.1286 - val_accuracy: 0.8762 - val_loss: 0.7861 - learning_rate: 1.0000e-04
# Epoch 63/100
# 303/303 - 13s - 44ms/step - accuracy: 0.9448 - loss: 0.1281 - val_accuracy: 0.8773 - val_loss: 0.8004 - learning_rate: 1.0000e-04
# Epoch 64/100
# 303/303 - 13s - 43ms/step - accuracy: 0.9447 - loss: 0.1292 - val_accuracy: 0.8771 - val_loss: 0.7216 - learning_rate: 1.0000e-04
# Epoch 65/100
# 303/303 - 13s - 43ms/step - accuracy: 0.9452 - loss: 0.1282 - val_accuracy: 0.8773 - val_loss: 0.7790 - learning_rate: 1.0000e-04
# Epoch 66/100
# 303/303 - 13s - 43ms/step - accuracy: 0.9449 - loss: 0.1288 - val_accuracy: 0.8756 - val_loss: 0.8436 - learning_rate: 1.0000e-04
# Epoch 67/100
# 303/303 - 13s - 44ms/step - accuracy: 0.9452 - loss: 0.1287 - val_accuracy: 0.8754 - val_loss: 0.7749 - learning_rate: 1.0000e-04
# Epoch 68/100
# 303/303 - 13s - 43ms/step - accuracy: 0.9453 - loss: 0.1282 - val_accuracy: 0.8762 - val_loss: 0.7890 - learning_rate: 1.0000e-04
# Epoch 69/100
# 303/303 - 13s - 43ms/step - accuracy: 0.9451 - loss: 0.1296 - val_accuracy: 0.8757 - val_loss: 0.8066 - learning_rate: 1.0000e-04
# Epoch 70/100
# 303/303 - 13s - 44ms/step - accuracy: 0.9455 - loss: 0.1279 - val_accuracy: 0.8751 - val_loss: 0.7949 - learning_rate: 1.0000e-04
# Epoch 71/100
# 303/303 - 13s - 43ms/step - accuracy: 0.9448 - loss: 0.1275 - val_accuracy: 0.8762 - val_loss: 0.7850 - learning_rate: 1.0000e-04
# Epoch 72/100
# 303/303 - 13s - 43ms/step - accuracy: 0.9453 - loss: 0.1276 - val_accuracy: 0.8757 - val_loss: 0.8461 - learning_rate: 1.0000e-04
# Epoch 73/100
# 303/303 - 13s - 44ms/step - accuracy: 0.9451 - loss: 0.1276 - val_accuracy: 0.8766 - val_loss: 0.7724 - learning_rate: 1.0000e-04
# Figure(1000x600)
# 379/379 ━━━━━━━━━━━━━━━━━━━━ 5s 10ms/step
# Accuracy: 0.875619425173439
# Classification Report:
#               precision    recall  f1-score   support
#
#         Safe       0.90      0.93      0.91      8371
#   Vulnerable       0.83      0.76      0.79      3737
#
#     accuracy                           0.88     12108
#    macro avg       0.86      0.84      0.85     12108
# weighted avg       0.87      0.88      0.87     12108


