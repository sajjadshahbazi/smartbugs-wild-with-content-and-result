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
from tensorflow.keras.layers import Embedding, Bidirectional, LSTM, Dropout, Dense
from tensorflow.keras.callbacks import EarlyStopping
from tensorflow.keras.optimizers import Adam
import tensorflow as tf
from tensorflow.python.platform import build_info as tf_build_info
from tensorflow.keras.layers import Input
from tensorflow.keras.layers import Conv2D, LeakyReLU, Cropping2D, MaxPooling2D, UpSampling2D, concatenate, Flatten, Dense, Bidirectional, LSTM, Input, Reshape, BatchNormalization, Reshape
from tensorflow.keras.models import Model
from tensorflow.keras import layers, models
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.callbacks import EarlyStopping
import matplotlib.pyplot as plt
from sklearn.metrics import classification_report, accuracy_score




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
    print(f"========== {folder}")
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
    for operator in SENSITIVE_OPERATORS_REETRANCY:
        if operator in function_body:
            return True
    return False


def save_to_file(data, file_prefix, cache_dir, batch_size, batch_index):
    os.makedirs(cache_dir, exist_ok=True)  # اطمینان از وجود پوشه CACHE_DIR
    for i in range(0, len(data), batch_size):
        batch = data[i:i + batch_size]
        filename = f"{file_prefix}_batch_{batch_index}_{i // batch_size}.pkl"  # نام‌گذاری دسته‌بندی‌شده
        filepath = os.path.join(cache_dir, filename)
        with open(filepath, 'wb') as f:
            pickle.dump(batch, f)
        print(f"Saved batch to {filepath}")

def extract_functions(code):
    functions = []

    # الگوی regex برای شناسایی فانکشن‌ها
    function_pattern = re.compile(
        r'function\s+\w+\s*\(.*\)\s*(public|private|internal|external)*\s*(view|pure)*\s*(returns\s*\(.*\))?\s*{')

    matches = function_pattern.finditer(code)
    for match in matches:
        function_start = match.start()
        function_end = code.find('}', function_start) + 1

        if function_end != -1:
            functions.append(code[function_start:function_end])
    return functions


def tokenize_solidity_code(code):
    pattern = r'\b(?:function|returns|uint256|internal|constant|assert|return|require|if|else|for|while)\b|[=<>!*&|()+\-;/\}]|\b[a-zA-Z_][a-zA-Z0-9_]*\b'
    tokens = re.findall(pattern, code)
    return tokens

def normalize_variables(tokens):
    normalized_tokens = []
    for token in tokens:
        if re.match(r'[a-zA-Z_][a-zA-Z0-9_]*', token) and token not in ['function', 'returns', 'internal', 'constant', 'assert', 'return']:
            normalized_tokens.append('VAR')  # به جای اسم متغیر، 'VAR' قرار می‌دهیم
        elif token in ['}', '{', '(', ')', '[', ']', '.', ';', ',', '+', '-', '=', '!', '?', ':']:
            normalized_tokens.append(token)
        elif token.strip() == '':
            continue
        else:
            normalized_tokens.append(token)
    return normalized_tokens

def extract_functions_with_bodies(contract_code):
    functions = []
    function_pattern = re.compile(
        r'function\s+\w+\s*\(.*?\)\s*(public|private|internal|external)?\s*(view|pure)?\s*(returns\s*\(.*?\))?\s*{')

    lines = contract_code.splitlines()  # تقسیم کد به خطوط
    open_brackets = 0
    in_function = False
    function_body = []
    start_line = 0

    for i, line in enumerate(lines):
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
    word2vec_model = Word2Vec(sentences=[tokens], vector_size=vector_length, window=5, min_count=1, workers=4)
    embeddings = [
        word2vec_model.wv[word] if word in word2vec_model.wv else np.zeros(vector_length)
        for word in tokens
    ]
    embeddings = embeddings[:sequence_length] + [np.zeros(vector_length)] * max(0, sequence_length - len(embeddings))
    return np.array(embeddings, dtype='float32')


def label_functions_by_vulnerable_lines(functions, vulnerable_lines):
    for func in functions:
        if any(func['start_line'] <= line <= func['end_line'] for line in vulnerable_lines):
            func['label'] = 1


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
            functions = extract_functions_with_bodies(contract_content)
            name = Path(file).stem
            res, vulnerable_lines = getResultVulnarable(name, target_vulnerability)
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





# def prepare_data_for_unet(X):
#     """ تبدیل داده‌های ورودی سه‌بعدی به فرمت مناسب برای U-Net """
#     return np.expand_dims(X, axis=-1)  # تبدیل به (samples, sequence_length, vector_length, 1)

def prepare_data_for_unet(X, target_shape=(50, 300)):
    """
    تبدیل داده‌های ورودی سه‌بعدی به فرمت مناسب برای U-Net
    ورودی: X به شکل (samples, sequence_length, vector_length)
    خروجی: X به شکل (samples, 50, 300, 1) برای ورودی U-Net
    """
    return np.expand_dims(X, axis=-1)  # تبدیل به (samples, sequence_length, vector_length, 1)


def build_unet(input_shape):
    """
    ساختار U-Net برای ورودی با ابعاد (50, 300, 1)
    و بررسی دقیق ابعاد برای جلوگیری از خطاهای concatenate
    """
    inputs = Input(input_shape)

    # --- 👇 مرحله Encoder ---
    conv1 = Conv2D(64, (3, 5), activation='relu', padding='same')(inputs)
    pool1 = MaxPooling2D((2, 2), padding='same')(conv1)

    conv2 = Conv2D(128, (3, 5), activation='relu', padding='same')(pool1)
    pool2 = MaxPooling2D((2, 2), padding='same')(conv2)

    conv3 = Conv2D(256, (3, 5), activation='relu', padding='same')(pool2)

    # --- 👇 مرحله Decoder ---
    up1 = UpSampling2D((2, 2))(conv3)

    # 🔍 بررسی ابعاد قبل از concatenate
    print(f"🔹 Shape of conv2: {conv2.shape}")
    print(f"🔹 Shape of up1: {up1.shape}")

    # 🚀 حل مشکل ابعاد در concatenate
    if up1.shape[1] != conv2.shape[1]:  # اگر ابعاد در ارتفاع تطابق نداشت
        up1 = Cropping2D(((1, 0), (0, 0)))(up1)
    if up1.shape[2] != conv2.shape[2]:  # اگر ابعاد در عرض تطابق نداشت
        up1 = Cropping2D(((0, 0), (1, 0)))(up1)

    concat1 = concatenate([conv2, up1])

    conv4 = Conv2D(128, (3, 5), activation='relu', padding='same')(concat1)
    up2 = UpSampling2D((2, 2))(conv4)

    # 🔍 بررسی ابعاد قبل از concatenate دوم
    print(f"🔹 Shape of conv1: {conv1.shape}")
    print(f"🔹 Shape of up2: {up2.shape}")

    # 🚀 حل مشکل ابعاد در concatenate دوم
    if up2.shape[1] != conv1.shape[1]:  # اگر ابعاد در ارتفاع تطابق نداشت
        up2 = Cropping2D(((1, 0), (0, 0)))(up2)
    if up2.shape[2] != conv1.shape[2]:  # اگر ابعاد در عرض تطابق نداشت
        up2 = Cropping2D(((0, 0), (1, 0)))(up2)

    concat2 = concatenate([conv1, up2])

    conv5 = Conv2D(64, (3, 5), activation='relu', padding='same')(concat2)
    outputs = Conv2D(1, (1, 1), activation='sigmoid')(conv5)

    return Model(inputs, outputs)



def lstm_unet_model(input_shape):
    inputs = tf.keras.Input(shape=input_shape)

    # 📌 مرحله LSTM (پردازش توالی‌ها)
    lstm = layers.Bidirectional(layers.LSTM(128, return_sequences=True))(inputs)
    lstm = layers.Bidirectional(layers.LSTM(64, return_sequences=True))(lstm)

    # 📌 مسیر نزولی U-Net (Encoder)
    conv1 = layers.Conv1D(64, kernel_size=3, activation='relu', padding='same')(lstm)
    conv1 = layers.Conv1D(64, kernel_size=3, activation='relu', padding='same')(conv1)
    pool1 = layers.MaxPooling1D(pool_size=2)(conv1)

    conv2 = layers.Conv1D(128, kernel_size=3, activation='relu', padding='same')(pool1)
    conv2 = layers.Conv1D(128, kernel_size=3, activation='relu', padding='same')(conv2)
    pool2 = layers.MaxPooling1D(pool_size=2)(conv2)

    # 📌 Bottleneck
    conv3 = layers.Conv1D(256, kernel_size=3, activation='relu', padding='same')(pool2)
    conv3 = layers.Conv1D(256, kernel_size=3, activation='relu', padding='same')(conv3)

    # 📌 مسیر صعودی U-Net (Decoder) - اصلاح شده
    up1 = layers.Conv1DTranspose(128, kernel_size=3, strides=2, padding='same', activation='relu')(conv3)
    concat1 = layers.concatenate([up1, conv2])  # دیگر نیازی به Cropping نداریم
    conv4 = layers.Conv1D(128, kernel_size=3, activation='relu', padding='same')(concat1)
    conv4 = layers.Conv1D(128, kernel_size=3, activation='relu', padding='same')(conv4)

    up2 = layers.Conv1DTranspose(64, kernel_size=3, strides=2, padding='same', activation='relu')(conv4)
    concat2 = layers.concatenate([up2, conv1])
    conv5 = layers.Conv1D(64, kernel_size=3, activation='relu', padding='same')(concat2)
    conv5 = layers.Conv1D(64, kernel_size=3, activation='relu', padding='same')(conv5)

    outputs = layers.Conv1D(1, kernel_size=1, activation='sigmoid')(conv5)  # احتمال آسیب‌پذیری

    model = models.Model(inputs, outputs)
    return model


def train_unet_lstm():
    X, Y = load_batches(CACHE_DIR, file_extension=".pkl")
    X_train, X_test, Y_train, Y_test = train_test_split(X, Y, test_size=0.2, random_state=42)

    # 📌 مدل LSTM + U-Net را تعریف و کامپایل کن
    input_shape = (X_train.shape[1], X_train.shape[2])  # (sequence_length, vector_length)
    model = lstm_unet_model(input_shape)
    model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])

    # 📌 آموزش مدل
    early_stopping = EarlyStopping(monitor='val_loss', patience=10, restore_best_weights=True)

    history = model.fit(
        X_train, Y_train,
        epochs=50, batch_size=32,
        validation_split=0.2,
        callbacks=[early_stopping],  # Early Stopping برای جلوگیری از overfitting
        verbose=2
    )

    # 📌 ارزیابی مدل
    loss, accuracy = model.evaluate(X_test, Y_test)
    print(f"Test Loss: {loss:.4f}")
    print(f"Test Accuracy: {accuracy:.4f}")

    # 📌 پیش‌بینی روی داده‌های تست
    Y_pred = (model.predict(X_test) > 0.5).astype("int32")

    # 📌 محاسبه معیارهای ارزیابی
    accuracy = accuracy_score(Y_test, Y_pred)
    report = classification_report(Y_test, Y_pred, target_names=['Safe', 'Vulnerable'], labels=[0, 1])

    print(f"Accuracy: {accuracy}")
    print("Classification Report:")
    print(report)

    # 📌 ذخیره مدل نهایی
    model.save('LSTM_UNet_model.h5')
    print("مدل نهایی ذخیره شد.")

    # 📌 رسم نمودار دقت و خطا
    plt.figure(figsize=(10, 6))
    plt.plot(history.history['accuracy'], label='train acc', color='blue')
    plt.plot(history.history['val_accuracy'], label='val acc', color='yellow')
    plt.plot(history.history['loss'], label='train loss', color='red')
    plt.plot(history.history['val_loss'], label='val loss', color='green')
    plt.title('Model Accuracy and Loss')
    plt.xlabel('Epochs')
    plt.ylabel('Accuracy / Loss')
    plt.legend(loc='best')
    plt.grid()
    plt.show()




if __name__ == "__main__":
    # files = [os.path.join(PATH, f) for f in os.listdir(PATH) if f.endswith(".sol")]
    # print(f"size files {files.__len__()}")
    # for batch_index, i in enumerate(range(0, len(files), batch_size)):
    #     batch_files = files[i:i + batch_size]
    #     print(f"size batch_files {batch_files.__len__()}")
    #     process_batch_with_categorization(batch_files, target_vulner, batch_size, batch_index)


    train_unet_lstm()



