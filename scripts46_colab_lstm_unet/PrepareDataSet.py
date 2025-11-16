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
import PreProcessTools  # فایل PreProcessTools.py در کنار این فایل
import io
import seaborn as sns
from tensorflow.keras import backend as K
from sklearn.model_selection import train_test_split
from tensorflow.keras.models import Sequential
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix, roc_auc_score
from tensorflow.keras.layers import Conv1D, ZeroPadding1D, LeakyReLU, UpSampling1D, Concatenate, Dropout, GlobalAveragePooling1D, Bidirectional, LSTM, Input, Reshape, BatchNormalization, Add, MultiHeadAttention, Flatten, Dense, MaxPooling1D
from tensorflow.keras.models import Model
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
sequence_length = 70  # تغییر به 70
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
# CACHE_DIR = os.path.join(ROOT, 'vectorcollections01')  # پوشه جدید
# os.makedirs(CACHE_DIR, exist_ok=True)

ROOT = '/content/smartbugs-wild-with-content-and-result' # Linux
CACHE_DIR = os.path.join(ROOT, 'vectorcollections01') # Linux

cache_path = os.path.join(CACHE_DIR, 'tokenized_fragments.pkl')
vulnerability_fd = open(os.path.join(ROOT, 'metadata', 'vulnerabilities.csv'), 'w', encoding='utf-8')

# PATH = f"{ROOT}\\contracts\\"  # main data set
# PATH = f"{ROOT}\\contract\\"  # part of main data set
# PATH = f"{ROOT}\\contra\\"  # one smart contract

PATH = os.path.join(ROOT, 'contracts') # Linux
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
            filepath = os.path.join(folder, file)
            with open(filepath, 'rb') as f:
                X, Y = pickle.load(f)
                # اگر طول توالی با 70 مطابقت نداشت، پدینگ اعمال کن
                if X.shape[1] != sequence_length:
                    X = pad_sequences(X, maxlen=sequence_length, padding='post', dtype='float32')
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


# تابعی برای توکن‌سازی کد Solidity
def tokenize_solidity_code(code):
    # الگوی اصلاح‌شده برای شناسایی علائم خاص از جمله '}'
    pattern = r'\b(?:function|returns|uint256|internal|constant|assert|return|require|if|else|for|while)\b|[=<>!*&|()+\-;/\}]|\b[a-zA-Z_][a-zA-Z0-9_]*\b'

    # یافتن تمام توکن‌ها با استفاده از الگو
    tokens = re.findall(pattern, code)

    return tokens


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
    max_function_length = 70  # تغییر به 70

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

    # ذخیره دسته‌ها
    def save_batch(X, Y, prefix):
        if len(X) > 0:
            filepath = os.path.join(CACHE_DIR, f"{prefix}_batch_{batch_index}.pkl")
            with open(filepath, 'wb') as f:
                pickle.dump((np.array(X), np.array(Y)), f)
            print(f"Saved {len(X)} samples to {filepath}")

    save_batch(X_vulnerable, Y_vulnerable, "vulnerable")
    save_batch(X_sensitive_negative, Y_sensitive_negative, "sensitive_negative")
    save_batch(X_safe, Y_safe, "safe")


# اجرای پردازش دسته‌ای
def run_preprocessing():
    os.chdir(PATH)
    files = [os.path.join(PATH, f) for f in os.listdir(PATH) if f.endswith(".sol")]
    print(f"Found {len(files)} .sol files.")
    for i in range(0, len(files), batch_size):
        batch_files = files[i:i + batch_size]
        process_batch_with_categorization(batch_files, target_vulnerability_reentrancy, batch_size, i // batch_size)


def train_LSTM_UNET_improved():
    X, Y = load_batches(CACHE_DIR, file_extension=".pkl")
    print(f"Shape of X: {X.shape}")
    print(f"Shape of Y: {Y.shape}")
    print("Distribution in Y:", np.unique(Y, return_counts=True))
    X_train_full, X_test, Y_train_full, Y_test = train_test_split(X, Y, test_size=0.2, random_state=42)

    # تعریف مدل
    inputs = Input(shape=(sequence_length, vector_length))  # (70, 300)

    # شاخه LSTM
    lstm1 = Bidirectional(LSTM(256, return_sequences=True))(inputs)
    lstm2 = Bidirectional(LSTM(128))(lstm1)  # خروجی (batch_size, 256)
    lstm_output_reshaped = Reshape((1, 256))(lstm2)  # تغییر به 256

    # شاخه U-Net
    # Encoder
    conv1 = Conv1D(256, 3, padding='same')(inputs)  # (70, 256)
    conv1 = BatchNormalization()(conv1)
    conv1 = LeakyReLU(negative_slope=0.1)(conv1)
    conv1_residual = conv1
    conv1 = Conv1D(256, 3, padding='same')(conv1)
    conv1 = BatchNormalization()(conv1)
    conv1 = LeakyReLU(negative_slope=0.1)(conv1)
    conv1 = Add()([conv1, conv1_residual])
    pool1 = MaxPooling1D(2)(conv1)  # (35, 256)

    conv2 = Conv1D(512, 3, padding='same')(pool1)  # (35, 512)
    conv2 = BatchNormalization()(conv2)
    conv2 = LeakyReLU(negative_slope=0.1)(conv2)
    conv2_residual = conv2
    conv2 = Conv1D(512, 3, padding='same')(conv2)
    conv2 = BatchNormalization()(conv2)
    conv2 = LeakyReLU(negative_slope=0.1)(conv2)
    conv2 = Add()([conv2, conv2_residual])
    pool2 = MaxPooling1D(2)(conv2)  # (17, 512)

    conv3 = Conv1D(1024, 3, padding='same')(pool2)  # (17, 1024)
    conv3 = BatchNormalization()(conv3)
    conv3 = LeakyReLU(negative_slope=0.1)(conv3)
    conv3_residual = conv3
    conv3 = Conv1D(1024, 3, padding='same')(conv3)
    conv3 = BatchNormalization()(conv3)
    conv3 = LeakyReLU(negative_slope=0.1)(conv3)
    conv3 = Add()([conv3, conv3_residual])
    pool3 = MaxPooling1D(2)(conv3)  # (8, 1024)

    conv4 = Conv1D(2048, 3, padding='same')(pool3)  # (8, 2048)
    conv4 = BatchNormalization()(conv4)
    conv4 = LeakyReLU(negative_slope=0.1)(conv4)
    conv4_residual = conv4
    conv4 = Conv1D(2048, 3, padding='same')(conv4)
    conv4 = BatchNormalization()(conv4)
    conv4 = LeakyReLU(negative_slope=0.1)(conv4)
    conv4 = Add()([conv4, conv4_residual])

    # Decoder
    up5 = UpSampling1D(2)(conv4)  # (8 → 16)
    up5 = ZeroPadding1D(padding=(0, 1))(up5)  # تطابق با 17
    concat5 = Concatenate()([up5, conv3])
    conv5 = Conv1D(1024, 3, padding='same')(concat5)
    conv5 = BatchNormalization()(conv5)
    conv5 = LeakyReLU(negative_slope=0.1)(conv5)

    up6 = UpSampling1D(2)(conv5)  # (17 → 34)
    up6 = ZeroPadding1D(padding=(0, 1))(up6)  # تطابق با 35
    concat6 = Concatenate()([up6, conv2])
    conv6 = Conv1D(512, 3, padding='same')(concat6)
    conv6 = BatchNormalization()(conv6)
    conv6 = LeakyReLU(negative_slope=0.1)(conv6)

    up7 = UpSampling1D(2)(conv6)  # (35 → 70)
    concat7 = Concatenate()([up7, conv1])
    conv7 = Conv1D(256, 3, padding='same')(concat7)
    conv7 = BatchNormalization()(conv7)
    conv7 = LeakyReLU(negative_slope=0.1)(conv7)

    # لایه اضافی
    conv8 = Conv1D(512, 3, padding='same')(conv7)  # کاهش از 4096 به 512
    conv8 = BatchNormalization()(conv8)
    conv8 = LeakyReLU(negative_slope=0.1)(conv8)

    unet_output = GlobalAveragePooling1D()(conv8)
    unet_output = Dense(256, activation='relu')(unet_output)
    unet_output_reshaped = Reshape((1, 256))(unet_output)

    # ترکیب با Cross-Attention
    combined = MultiHeadAttention(num_heads=8, key_dim=256)(query=lstm_output_reshaped, value=unet_output_reshaped,
                                                            key=unet_output_reshaped)
    combined = Flatten()(combined)

    # لایه‌های نهایی
    dense1 = Dense(256, activation='relu')(combined)
    dense1 = Dropout(0.6)(dense1)
    dense2 = Dense(128, activation='relu')(dense1)
    dense2 = Dropout(0.6)(dense2)
    output = Dense(1, activation='sigmoid')(dense2)

    # ساخت مدل
    model = Model(inputs=inputs, outputs=output)
    model.compile(optimizer=Adam(learning_rate=0.0005), loss='binary_crossentropy', metrics=['accuracy'])

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
    print("Starting preprocessing with sequence_length = 70...")
    run_preprocessing()
    print("Preprocessing completed. Starting training...")
    train_LSTM_UNET_improved()