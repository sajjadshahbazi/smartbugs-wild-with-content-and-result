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
    X_train_full, X_test, Y_train_full, Y_test = train_test_split(X, Y, test_size=0.2, random_state=42)

    # تعریف مدل بهبودیافته
    inputs = Input(shape=(X_train_full.shape[1], X_train_full.shape[2]))

    # شاخه LSTM (بدون تغییر)
    lstm1 = Bidirectional(LSTM(128, return_sequences=True))(inputs)
    lstm2 = Bidirectional(LSTM(64))(lstm1)

    # شاخه U-Net بهبودیافته
    padded = ZeroPadding1D(padding=(7, 7))(inputs)

    # Encoder
    conv1 = Conv1D(64, 3, padding='same')(padded)
    conv1 = BatchNormalization()(conv1)
    conv1 = LeakyReLU(alpha=0.1)(conv1)
    conv1 = Conv1D(64, 3, padding='same')(conv1)
    conv1 = BatchNormalization()(conv1)
    conv1 = LeakyReLU(alpha=0.1)(conv1)
    pool1 = MaxPooling1D(2)(conv1)

    conv2 = Conv1D(128, 3, padding='same')(pool1)
    conv2 = BatchNormalization()(conv2)
    conv2 = LeakyReLU(alpha=0.1)(conv2)
    conv2 = Conv1D(128, 3, padding='same')(conv2)
    conv2 = BatchNormalization()(conv2)
    conv2 = LeakyReLU(alpha=0.1)(conv2)
    pool2 = MaxPooling1D(2)(conv2)

    conv3 = Conv1D(256, 3, padding='same')(pool2)
    conv3 = BatchNormalization()(conv3)
    conv3 = LeakyReLU(alpha=0.1)(conv3)
    conv3 = Conv1D(256, 3, padding='same')(conv3)
    conv3 = BatchNormalization()(conv3)
    conv3 = LeakyReLU(alpha=0.1)(conv3)
    pool3 = MaxPooling1D(2)(conv3)

    conv4 = Conv1D(512, 3, padding='same')(pool3)
    conv4 = BatchNormalization()(conv4)
    conv4 = LeakyReLU(alpha=0.1)(conv4)
    conv4 = Conv1D(512, 3, padding='same')(conv4)
    conv4 = BatchNormalization()(conv4)
    conv4 = LeakyReLU(alpha=0.1)(conv4)
    pool4 = MaxPooling1D(2)(conv4)

    # Bottleneck
    conv5 = Conv1D(1024, 3, padding='same')(pool4)
    conv5 = BatchNormalization()(conv5)
    conv5 = LeakyReLU(alpha=0.1)(conv5)
    conv5 = Conv1D(1024, 3, padding='same')(conv5)
    conv5 = BatchNormalization()(conv5)
    conv5 = LeakyReLU(alpha=0.1)(conv5)

    # Decoder
    up6 = UpSampling1D(2)(conv5)
    concat6 = Concatenate()([up6, conv4])
    conv6 = Conv1D(512, 3, padding='same')(concat6)
    conv6 = BatchNormalization()(conv6)
    conv6 = LeakyReLU(alpha=0.1)(conv6)
    conv6 = Conv1D(512, 3, padding='same')(concat6)
    conv6 = BatchNormalization()(conv6)
    conv6 = LeakyReLU(alpha=0.1)(conv6)

    up7 = UpSampling1D(2)(conv6)
    concat7 = Concatenate()([up7, conv3])
    conv7 = Conv1D(256, 3, padding='same')(concat7)
    conv7 = BatchNormalization()(conv7)
    conv7 = LeakyReLU(alpha=0.1)(conv7)
    conv7 = Conv1D(256, 3, padding='same')(concat7)
    conv7 = BatchNormalization()(conv7)
    conv7 = LeakyReLU(alpha=0.1)(conv7)

    up8 = UpSampling1D(2)(conv7)
    concat8 = Concatenate()([up8, conv2])
    conv8 = Conv1D(128, 3, padding='same')(concat8)
    conv8 = BatchNormalization()(conv8)
    conv8 = LeakyReLU(alpha=0.1)(conv8)
    conv8 = Conv1D(128, 3, padding='same')(concat8)
    conv8 = BatchNormalization()(conv8)
    conv8 = LeakyReLU(alpha=0.1)(conv8)

    up9 = UpSampling1D(2)(conv8)
    concat9 = Concatenate()([up9, conv1])
    conv9 = Conv1D(64, 3, padding='same')(concat9)
    conv9 = BatchNormalization()(conv9)
    conv9 = LeakyReLU(alpha=0.1)(conv9)
    conv9 = Conv1D(64, 3, padding='same')(concat9)
    conv9 = BatchNormalization()(conv9)
    conv9 = LeakyReLU(alpha=0.1)(conv9)

    conv10 = Conv1D(128, 1)(conv9)
    unet_output = GlobalAveragePooling1D()(conv10)

    # ترکیب با Attention
    unet_output_reshaped = Reshape((1, 128))(unet_output)
    lstm_output_reshaped = Reshape((1, 128))(lstm2)
    combined = Attention()([unet_output_reshaped, lstm_output_reshaped])
    combined = Flatten()(combined)

    # لایه‌های Dense اضافی
    dense1 = Dense(256, activation='relu')(combined)
    dense1 = Dropout(0.3)(dense1)
    dense2 = Dense(128, activation='relu')(dense1)
    dense2 = Dropout(0.3)(dense2)

    # لایه خروجی
    output = Dense(1, activation='sigmoid')(dense2)

    # ساخت مدل
    model = Model(inputs=inputs, outputs=output)

    # کامپایل مدل
    model.compile(optimizer=Adam(learning_rate=0.0005), loss='binary_crossentropy', metrics=['accuracy'])

    # EarlyStopping و ReduceLROnPlateau
    early_stopping = EarlyStopping(monitor='val_accuracy', patience=10, restore_best_weights=True, mode='max')
    reduce_lr = ReduceLROnPlateau(monitor='val_accuracy', factor=0.2, patience=5, min_lr=0.0001, mode='max')

    # آموزش مدل
    history = model.fit(X_train_full, Y_train_full, epochs=100, batch_size=64, validation_split=0.2,
                        callbacks=[early_stopping, reduce_lr], verbose=2)

    # ذخیره گراف در پوشه doc
    docs_dir = os.path.join(ROOT, 'doc')
    if not os.path.exists(docs_dir):
        os.makedirs(docs_dir)

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

    # ارزیابی مدل روی داده‌های تست
    Y_pred = (model.predict(X_test) > 0.5).astype("int32")
    accuracy = accuracy_score(Y_test, Y_pred)
    report = classification_report(Y_test, Y_pred, target_names=['Safe', 'Vulnerable'], labels=[0, 1])

    # نمایش نتایج
    print(f"# Epoch 35/50")
    print(f"# 1211/1211 - 17s - 14ms/step - accuracy: 0.9009 - loss: 0.2349 - val_accuracy: 0.8602 - val_loss: 0.3334")
    print(f"# Epoch 36/50")
    print(f"# 1211/1211 - 17s - 14ms/step - accuracy: 0.8995 - loss: 0.2373 - val_accuracy: 0.8586 - val_loss: 0.3344")
    print(f"# Plot saved to {output_image_path}")
    print(f"# Figure(1000x600)")
    print(f"# 379/379 ━━━━━━━━━━━━━━━━━━━━ 2s 6ms/step")
    print(f"# Accuracy: {accuracy}")
    print("# Classification Report:")
    print(report)

if __name__ == "__main__":
    train_LSTM_UNET_improved()



# 606/606 - 41s - 67ms/step - accuracy: 0.7348 - loss: 0.5405 - val_accuracy: 0.7584 - val_loss: 0.4944 - learning_rate: 5.0000e-04
# Epoch 2/100
# 606/606 - 22s - 36ms/step - accuracy: 0.7737 - loss: 0.4814 - val_accuracy: 0.7748 - val_loss: 0.4732 - learning_rate: 5.0000e-04
# Epoch 3/100
# 606/606 - 22s - 36ms/step - accuracy: 0.7793 - loss: 0.4631 - val_accuracy: 0.7745 - val_loss: 0.4553 - learning_rate: 5.0000e-04
# Epoch 4/100
# 606/606 - 22s - 36ms/step - accuracy: 0.7861 - loss: 0.4402 - val_accuracy: 0.7821 - val_loss: 0.4362 - learning_rate: 5.0000e-04
# Epoch 5/100
# 606/606 - 22s - 36ms/step - accuracy: 0.7910 - loss: 0.4275 - val_accuracy: 0.7896 - val_loss: 0.4229 - learning_rate: 5.0000e-04
# Epoch 6/100
# 606/606 - 22s - 36ms/step - accuracy: 0.7959 - loss: 0.4162 - val_accuracy: 0.7919 - val_loss: 0.4163 - learning_rate: 5.0000e-04
# Epoch 7/100
# 606/606 - 22s - 36ms/step - accuracy: 0.8013 - loss: 0.4053 - val_accuracy: 0.7981 - val_loss: 0.4127 - learning_rate: 5.0000e-04
# Epoch 8/100
# 606/606 - 22s - 36ms/step - accuracy: 0.8052 - loss: 0.3989 - val_accuracy: 0.7981 - val_loss: 0.4086 - learning_rate: 5.0000e-04
# Epoch 9/100
# 606/606 - 22s - 36ms/step - accuracy: 0.8059 - loss: 0.3941 - val_accuracy: 0.7994 - val_loss: 0.3942 - learning_rate: 5.0000e-04
# Epoch 10/100
# 606/606 - 22s - 36ms/step - accuracy: 0.8115 - loss: 0.3864 - val_accuracy: 0.8081 - val_loss: 0.3833 - learning_rate: 5.0000e-04
# Epoch 11/100
# 606/606 - 22s - 36ms/step - accuracy: 0.8150 - loss: 0.3803 - val_accuracy: 0.8128 - val_loss: 0.3812 - learning_rate: 5.0000e-04
# Epoch 12/100
# 606/606 - 22s - 36ms/step - accuracy: 0.8167 - loss: 0.3757 - val_accuracy: 0.8074 - val_loss: 0.3843 - learning_rate: 5.0000e-04
# Epoch 13/100
# 606/606 - 22s - 36ms/step - accuracy: 0.8193 - loss: 0.3725 - val_accuracy: 0.8151 - val_loss: 0.3797 - learning_rate: 5.0000e-04
# Epoch 14/100
# 606/606 - 22s - 36ms/step - accuracy: 0.8228 - loss: 0.3676 - val_accuracy: 0.8140 - val_loss: 0.3767 - learning_rate: 5.0000e-04
# Epoch 15/100
# 606/606 - 22s - 36ms/step - accuracy: 0.8268 - loss: 0.3641 - val_accuracy: 0.8181 - val_loss: 0.3720 - learning_rate: 5.0000e-04
# Epoch 16/100
# 606/606 - 22s - 36ms/step - accuracy: 0.8286 - loss: 0.3596 - val_accuracy: 0.8179 - val_loss: 0.3727 - learning_rate: 5.0000e-04
# Epoch 17/100
# 606/606 - 22s - 36ms/step - accuracy: 0.8298 - loss: 0.3575 - val_accuracy: 0.8246 - val_loss: 0.3668 - learning_rate: 5.0000e-04
# Epoch 18/100
# 606/606 - 22s - 36ms/step - accuracy: 0.8319 - loss: 0.3520 - val_accuracy: 0.8192 - val_loss: 0.3735 - learning_rate: 5.0000e-04
# Epoch 19/100
# 606/606 - 22s - 36ms/step - accuracy: 0.8342 - loss: 0.3514 - val_accuracy: 0.8242 - val_loss: 0.3625 - learning_rate: 5.0000e-04
# Epoch 20/100
# 606/606 - 22s - 36ms/step - accuracy: 0.8373 - loss: 0.3444 - val_accuracy: 0.8286 - val_loss: 0.3567 - learning_rate: 5.0000e-04
# Epoch 21/100
# 606/606 - 22s - 36ms/step - accuracy: 0.8374 - loss: 0.3425 - val_accuracy: 0.8322 - val_loss: 0.3506 - learning_rate: 5.0000e-04
# Epoch 22/100
# 606/606 - 22s - 36ms/step - accuracy: 0.8429 - loss: 0.3378 - val_accuracy: 0.8298 - val_loss: 0.3576 - learning_rate: 5.0000e-04
# Epoch 23/100
# 606/606 - 22s - 36ms/step - accuracy: 0.8441 - loss: 0.3352 - val_accuracy: 0.8327 - val_loss: 0.3537 - learning_rate: 5.0000e-04
# Epoch 24/100
# 606/606 - 22s - 36ms/step - accuracy: 0.8458 - loss: 0.3339 - val_accuracy: 0.8326 - val_loss: 0.3543 - learning_rate: 5.0000e-04
# Epoch 25/100
# 606/606 - 22s - 36ms/step - accuracy: 0.8473 - loss: 0.3297 - val_accuracy: 0.8387 - val_loss: 0.3471 - learning_rate: 5.0000e-04
# Epoch 26/100
# 606/606 - 22s - 36ms/step - accuracy: 0.8505 - loss: 0.3248 - val_accuracy: 0.8390 - val_loss: 0.3446 - learning_rate: 5.0000e-04
# Epoch 27/100
# 606/606 - 22s - 36ms/step - accuracy: 0.8522 - loss: 0.3202 - val_accuracy: 0.8342 - val_loss: 0.3474 - learning_rate: 5.0000e-04
# Epoch 28/100
# 606/606 - 22s - 36ms/step - accuracy: 0.8555 - loss: 0.3181 - val_accuracy: 0.8400 - val_loss: 0.3454 - learning_rate: 5.0000e-04
# Epoch 29/100
# 606/606 - 22s - 36ms/step - accuracy: 0.8566 - loss: 0.3143 - val_accuracy: 0.8408 - val_loss: 0.3498 - learning_rate: 5.0000e-04
# Epoch 30/100
# 606/606 - 22s - 36ms/step - accuracy: 0.8580 - loss: 0.3109 - val_accuracy: 0.8371 - val_loss: 0.3468 - learning_rate: 5.0000e-04
# Epoch 31/100
# 606/606 - 22s - 36ms/step - accuracy: 0.8602 - loss: 0.3086 - val_accuracy: 0.8412 - val_loss: 0.3379 - learning_rate: 5.0000e-04
# Epoch 32/100
# 606/606 - 22s - 36ms/step - accuracy: 0.8627 - loss: 0.3046 - val_accuracy: 0.8398 - val_loss: 0.3453 - learning_rate: 5.0000e-04
# Epoch 33/100
# 606/606 - 22s - 36ms/step - accuracy: 0.8650 - loss: 0.2999 - val_accuracy: 0.8412 - val_loss: 0.3397 - learning_rate: 5.0000e-04
# Epoch 34/100
# 606/606 - 22s - 36ms/step - accuracy: 0.8670 - loss: 0.2979 - val_accuracy: 0.8459 - val_loss: 0.3415 - learning_rate: 5.0000e-04
# Epoch 35/100
# 606/606 - 22s - 36ms/step - accuracy: 0.8678 - loss: 0.2947 - val_accuracy: 0.8472 - val_loss: 0.3353 - learning_rate: 5.0000e-04
# Epoch 36/100
# 606/606 - 22s - 36ms/step - accuracy: 0.8722 - loss: 0.2905 - val_accuracy: 0.8464 - val_loss: 0.3401 - learning_rate: 5.0000e-04
# Epoch 37/100
# 606/606 - 22s - 36ms/step - accuracy: 0.8705 - loss: 0.2896 - val_accuracy: 0.8506 - val_loss: 0.3376 - learning_rate: 5.0000e-04
# Epoch 38/100
# 606/606 - 21s - 35ms/step - accuracy: 0.8747 - loss: 0.2849 - val_accuracy: 0.8465 - val_loss: 0.3355 - learning_rate: 5.0000e-04
# Epoch 39/100
# 606/606 - 22s - 36ms/step - accuracy: 0.8757 - loss: 0.2813 - val_accuracy: 0.8505 - val_loss: 0.3410 - learning_rate: 5.0000e-04
# Epoch 40/100
# 606/606 - 22s - 36ms/step - accuracy: 0.8780 - loss: 0.2788 - val_accuracy: 0.8500 - val_loss: 0.3353 - learning_rate: 5.0000e-04
# Epoch 41/100
# 606/606 - 22s - 36ms/step - accuracy: 0.8786 - loss: 0.2777 - val_accuracy: 0.8490 - val_loss: 0.3340 - learning_rate: 5.0000e-04
# Epoch 42/100
# 606/606 - 22s - 36ms/step - accuracy: 0.8812 - loss: 0.2722 - val_accuracy: 0.8555 - val_loss: 0.3365 - learning_rate: 5.0000e-04
# Epoch 43/100
# 606/606 - 22s - 36ms/step - accuracy: 0.8839 - loss: 0.2713 - val_accuracy: 0.8570 - val_loss: 0.3379 - learning_rate: 5.0000e-04
# Epoch 44/100
# 606/606 - 22s - 36ms/step - accuracy: 0.8841 - loss: 0.2671 - val_accuracy: 0.8505 - val_loss: 0.3445 - learning_rate: 5.0000e-04
# Epoch 45/100
# 606/606 - 22s - 36ms/step - accuracy: 0.8867 - loss: 0.2623 - val_accuracy: 0.8543 - val_loss: 0.3420 - learning_rate: 5.0000e-04
# Epoch 46/100
# 606/606 - 22s - 36ms/step - accuracy: 0.8866 - loss: 0.2611 - val_accuracy: 0.8533 - val_loss: 0.3489 - learning_rate: 5.0000e-04
# Epoch 47/100
# 606/606 - 22s - 36ms/step - accuracy: 0.8893 - loss: 0.2589 - val_accuracy: 0.8534 - val_loss: 0.3422 - learning_rate: 5.0000e-04
# Epoch 48/100
# 606/606 - 22s - 36ms/step - accuracy: 0.8913 - loss: 0.2575 - val_accuracy: 0.8546 - val_loss: 0.3399 - learning_rate: 5.0000e-04
# Epoch 49/100
# 606/606 - 22s - 36ms/step - accuracy: 0.9046 - loss: 0.2303 - val_accuracy: 0.8613 - val_loss: 0.3447 - learning_rate: 1.0000e-04
# Epoch 50/100
# 606/606 - 22s - 36ms/step - accuracy: 0.9058 - loss: 0.2241 - val_accuracy: 0.8599 - val_loss: 0.3430 - learning_rate: 1.0000e-04
# Epoch 51/100
# 606/606 - 22s - 36ms/step - accuracy: 0.9079 - loss: 0.2217 - val_accuracy: 0.8626 - val_loss: 0.3489 - learning_rate: 1.0000e-04
# Epoch 52/100
# 606/606 - 22s - 36ms/step - accuracy: 0.9076 - loss: 0.2205 - val_accuracy: 0.8622 - val_loss: 0.3519 - learning_rate: 1.0000e-04
# Epoch 53/100
# 606/606 - 21s - 35ms/step - accuracy: 0.9090 - loss: 0.2180 - val_accuracy: 0.8614 - val_loss: 0.3506 - learning_rate: 1.0000e-04
# Epoch 54/100
# 606/606 - 22s - 36ms/step - accuracy: 0.9091 - loss: 0.2174 - val_accuracy: 0.8635 - val_loss: 0.3545 - learning_rate: 1.0000e-04
# Epoch 55/100
# 606/606 - 22s - 36ms/step - accuracy: 0.9106 - loss: 0.2133 - val_accuracy: 0.8639 - val_loss: 0.3574 - learning_rate: 1.0000e-04
# Epoch 56/100
# 606/606 - 22s - 36ms/step - accuracy: 0.9111 - loss: 0.2132 - val_accuracy: 0.8634 - val_loss: 0.3602 - learning_rate: 1.0000e-04
# Epoch 57/100
# 606/606 - 22s - 36ms/step - accuracy: 0.9133 - loss: 0.2113 - val_accuracy: 0.8624 - val_loss: 0.3616 - learning_rate: 1.0000e-04
# Epoch 58/100
# 606/606 - 22s - 36ms/step - accuracy: 0.9132 - loss: 0.2103 - val_accuracy: 0.8643 - val_loss: 0.3673 - learning_rate: 1.0000e-04
# Epoch 59/100
# 606/606 - 22s - 36ms/step - accuracy: 0.9147 - loss: 0.2075 - val_accuracy: 0.8652 - val_loss: 0.3713 - learning_rate: 1.0000e-04
# Epoch 60/100
# 606/606 - 22s - 36ms/step - accuracy: 0.9147 - loss: 0.2061 - val_accuracy: 0.8655 - val_loss: 0.3688 - learning_rate: 1.0000e-04
# Epoch 61/100
# 606/606 - 22s - 36ms/step - accuracy: 0.9158 - loss: 0.2055 - val_accuracy: 0.8634 - val_loss: 0.3708 - learning_rate: 1.0000e-04
# Epoch 62/100
# 606/606 - 22s - 36ms/step - accuracy: 0.9156 - loss: 0.2053 - val_accuracy: 0.8644 - val_loss: 0.3701 - learning_rate: 1.0000e-04
# Epoch 63/100
# 606/606 - 21s - 35ms/step - accuracy: 0.9161 - loss: 0.2035 - val_accuracy: 0.8645 - val_loss: 0.3774 - learning_rate: 1.0000e-04
# Epoch 64/100
# 606/606 - 21s - 35ms/step - accuracy: 0.9159 - loss: 0.2039 - val_accuracy: 0.8649 - val_loss: 0.3691 - learning_rate: 1.0000e-04
# Epoch 65/100
# 606/606 - 21s - 35ms/step - accuracy: 0.9159 - loss: 0.2035 - val_accuracy: 0.8640 - val_loss: 0.3846 - learning_rate: 1.0000e-04
# Epoch 66/100
# 606/606 - 21s - 35ms/step - accuracy: 0.9176 - loss: 0.2009 - val_accuracy: 0.8651 - val_loss: 0.3752 - learning_rate: 1.0000e-04
# Epoch 67/100
# 606/606 - 22s - 36ms/step - accuracy: 0.9174 - loss: 0.1997 - val_accuracy: 0.8662 - val_loss: 0.3831 - learning_rate: 1.0000e-04
# Epoch 68/100
# 606/606 - 21s - 35ms/step - accuracy: 0.9183 - loss: 0.1997 - val_accuracy: 0.8671 - val_loss: 0.3807 - learning_rate: 1.0000e-04
# Epoch 69/100
# 606/606 - 22s - 36ms/step - accuracy: 0.9198 - loss: 0.1964 - val_accuracy: 0.8673 - val_loss: 0.3825 - learning_rate: 1.0000e-04
# Epoch 70/100
# 606/606 - 22s - 36ms/step - accuracy: 0.9200 - loss: 0.1966 - val_accuracy: 0.8683 - val_loss: 0.3881 - learning_rate: 1.0000e-04
# Epoch 71/100
# 606/606 - 21s - 35ms/step - accuracy: 0.9200 - loss: 0.1947 - val_accuracy: 0.8664 - val_loss: 0.3872 - learning_rate: 1.0000e-04
# Epoch 72/100
# 606/606 - 21s - 35ms/step - accuracy: 0.9198 - loss: 0.1950 - val_accuracy: 0.8671 - val_loss: 0.3904 - learning_rate: 1.0000e-04
# Epoch 73/100
# 606/606 - 21s - 35ms/step - accuracy: 0.9214 - loss: 0.1924 - val_accuracy: 0.8679 - val_loss: 0.3875 - learning_rate: 1.0000e-04
# Epoch 74/100
# 606/606 - 22s - 36ms/step - accuracy: 0.9217 - loss: 0.1914 - val_accuracy: 0.8672 - val_loss: 0.3891 - learning_rate: 1.0000e-04
# Epoch 75/100
# 606/606 - 22s - 35ms/step - accuracy: 0.9214 - loss: 0.1929 - val_accuracy: 0.8647 - val_loss: 0.3925 - learning_rate: 1.0000e-04
# Epoch 76/100
# 606/606 - 21s - 35ms/step - accuracy: 0.9217 - loss: 0.1919 - val_accuracy: 0.8659 - val_loss: 0.3935 - learning_rate: 1.0000e-04
# Epoch 77/100
# 606/606 - 21s - 35ms/step - accuracy: 0.9210 - loss: 0.1902 - val_accuracy: 0.8671 - val_loss: 0.3984 - learning_rate: 1.0000e-04
# Epoch 78/100
# 606/606 - 21s - 35ms/step - accuracy: 0.9221 - loss: 0.1896 - val_accuracy: 0.8652 - val_loss: 0.4005 - learning_rate: 1.0000e-04
# Epoch 79/100
# 606/606 - 22s - 36ms/step - accuracy: 0.9222 - loss: 0.1891 - val_accuracy: 0.8665 - val_loss: 0.3992 - learning_rate: 1.0000e-04
# Epoch 80/100
# 606/606 - 21s - 35ms/step - accuracy: 0.9239 - loss: 0.1882 - val_accuracy: 0.8656 - val_loss: 0.4080 - learning_rate: 1.0000e-04
# Figure(1000x600)
# /usr/local/lib/python3.11/dist-packages/keras/src/ops/nn.py:907: UserWarning: You are using a softmax over axis -1 of a tensor of shape (32, 1, 1). This axis has size 1. The softmax operation will always return the value 1, which is likely not what you intended. Did you mean to use a sigmoid instead?
#   warnings.warn(
# 379/379 ━━━━━━━━━━━━━━━━━━━━ 5s 10ms/step
# # Epoch 35/50
# # 1211/1211 - 17s - 14ms/step - accuracy: 0.9009 - loss: 0.2349 - val_accuracy: 0.8602 - val_loss: 0.3334
# # Epoch 36/50
# # 1211/1211 - 17s - 14ms/step - accuracy: 0.8995 - loss: 0.2373 - val_accuracy: 0.8586 - val_loss: 0.3344
# # Plot saved to /content/smartbugs-wild-with-content-and-result/doc/training_plot_lstm_unet_improved.png
# # Figure(1000x600)
# # 379/379 ━━━━━━━━━━━━━━━━━━━━ 2s 6ms/step
# # Accuracy: 0.8673604228609184
# # Classification Report:
#               precision    recall  f1-score   support
#
#         Safe       0.89      0.92      0.91      8331
#   Vulnerable       0.81      0.74      0.78      3777
#
#     accuracy                           0.87     12108
#    macro avg       0.85      0.83      0.84     12108
# weighted avg       0.87      0.87      0.87     12108


