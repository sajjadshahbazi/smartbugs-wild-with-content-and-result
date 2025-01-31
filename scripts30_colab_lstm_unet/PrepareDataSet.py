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


# def prepare_data_for_unet(X, target_shape=(50, 300)):
#     """
#     تبدیل داده‌های ورودی سه‌بعدی به فرمت مناسب برای U-Net
#
#     :param X: آرایه ورودی با شکل (samples, sequence_length, vector_length)
#     :param target_shape: ابعاد نهایی که باید به U-Net داده شود (باید هم‌اندازه با ورودی اصلی باشد)
#     :return: آرایه‌ای با ابعاد (samples, 50, 300, 1) برای استفاده در U-Net
#     """
#     if X.shape[1:] != target_shape:
#         raise ValueError(f"❌ ابعاد داده ورودی با {target_shape} سازگار نیست! شکل فعلی: {X.shape}")
#
#     # ✅ اضافه کردن یک بعد کانال برای سازگاری با U-Net
#     X = np.expand_dims(X, axis=-1)  # تبدیل به (samples, sequence_length, vector_length, 1)
#
#     print("\n🔍 **بررسی داده‌های تبدیل‌شده برای U-Net:**")
#     print("🔹 شکل نهایی X برای U-Net:", X.shape)
#     print("🔹 بیشینه مقدار X:", np.max(X))
#     print("🔹 کمینه مقدار X:", np.min(X))
#     print("🔹 میانگین مقدار X:", np.mean(X))
#
#     return X

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



def build_unet_lstm(input_shape_unet, input_shape_lstm):
    """
    ترکیب U-Net و LSTM
    """
    # **U-Net Model**
    unet_model = build_unet(input_shape_unet)

    # **تبدیل خروجی U-Net به فرمت مناسب برای LSTM**
    lstm_input = Reshape((50, 300))(unet_model.output)  # حفظ ساختار داده بدون Flatten

    # **LSTM Layers**
    lstm_layer = Bidirectional(LSTM(128, return_sequences=True))(lstm_input)
    lstm_layer = Bidirectional(LSTM(64))(lstm_layer)

    # **Fully Connected Layers**
    dense1 = Dense(128, activation='relu')(lstm_layer)
    dense2 = Dense(64, activation='relu')(dense1)
    outputs = Dense(1, activation='sigmoid')(dense2)

    return Model(inputs=[unet_model.input], outputs=outputs)

def train_unet_lstm():
    # **بارگذاری داده‌ها**
    X, Y = load_batches(CACHE_DIR, file_extension=".pkl")

    # **تبدیل داده‌ها برای U-Net**
    X_unet = prepare_data_for_unet(X, target_shape=(50, 300))

    # **تقسیم داده‌ها**
    X_train_lstm, X_test_lstm, X_train_unet, X_test_unet, Y_train, Y_test = train_test_split(
        X, X_unet, Y, test_size=0.2, random_state=42
    )

    # **ساخت مدل**
    model = build_unet_lstm((50, 300, 1), (X.shape[1], X.shape[2]))

    model.compile(
        optimizer=Adam(learning_rate=0.001),
        loss="binary_crossentropy",
        metrics=['accuracy']
    )

    # **آموزش مدل**
    history = model.fit(
        [X_train_unet], Y_train,
        epochs=50, batch_size=32, validation_split=0.2, verbose=2
    )

    # **نمایش نمودار آموزش**
    plt.figure(figsize=(10, 6))
    plt.plot(history.history['accuracy'], label='Train Accuracy', color='blue')
    plt.plot(history.history['val_accuracy'], label='Validation Accuracy', color='orange')
    plt.plot(history.history['loss'], label='Train Loss', color='red')
    plt.plot(history.history['val_loss'], label='Validation Loss', color='green')
    plt.title('Training and Validation Metrics')
    plt.xlabel('Epochs')
    plt.ylabel('Accuracy / Loss')
    plt.legend()
    plt.grid()
    plt.savefig("training_plot_unet_lstm.png", dpi=300, bbox_inches='tight')
    plt.show()

    # **ارزیابی مدل**
    Y_pred = (model.predict([X_test_unet]) > 0.5).astype("int32")
    accuracy = accuracy_score(Y_test, Y_pred)
    report = classification_report(Y_test, Y_pred, target_names=['Safe', 'Vulnerable'], labels=[0, 1])

    print(f"Accuracy: {accuracy}")
    print("Classification Report:")
    print(report)

    # **ذخیره مدل**
    model.save('final_unet_lstm_model.h5')
    print("Model training completed and saved.")




if __name__ == "__main__":
    # files = [os.path.join(PATH, f) for f in os.listdir(PATH) if f.endswith(".sol")]
    # print(f"size files {files.__len__()}")
    # for batch_index, i in enumerate(range(0, len(files), batch_size)):
    #     batch_files = files[i:i + batch_size]
    #     print(f"size batch_files {batch_files.__len__()}")
    #     process_batch_with_categorization(batch_files, target_vulner, batch_size, batch_index)


    train_unet_lstm()


# 2025-01-31 16:22:26.441720: W tensorflow/core/common_runtime/gpu/gpu_bfc_allocator.cc:47] Overriding orig_value setting because the TF_FORCE_GPU_ALLOW_GROWTH environment variable is set. Original config value was 0.
# I0000 00:00:1738340546.441899   11614 gpu_device.cc:2022] Created device /job:localhost/replica:0/task:0/device:GPU:0 with 20967 MB memory:  -> device: 0, name: NVIDIA L4, pci bus id: 0000:00:03.0, compute capability: 8.9
# 🔹 Shape of conv2: (None, 25, 150, 128)
# 🔹 Shape of up1: (None, 26, 150, 256)
# 🔹 Shape of conv1: (None, 50, 300, 64)
# 🔹 Shape of up2: (None, 50, 300, 128)
# Epoch 1/50
# I0000 00:00:1738340558.282168   11726 cuda_dnn.cc:529] Loaded cuDNN version 90300
# 1211/1211 - 185s - 153ms/step - accuracy: 0.6845 - loss: 0.6254 - val_accuracy: 0.6887 - val_loss: 0.6266
# Epoch 2/50
# 1211/1211 - 170s - 140ms/step - accuracy: 0.6848 - loss: 0.6242 - val_accuracy: 0.6887 - val_loss: 0.6260
# Epoch 3/50
# 1211/1211 - 170s - 140ms/step - accuracy: 0.6848 - loss: 0.6238 - val_accuracy: 0.6887 - val_loss: 0.6204
# Epoch 4/50
# 1211/1211 - 170s - 140ms/step - accuracy: 0.6848 - loss: 0.6239 - val_accuracy: 0.6887 - val_loss: 0.6210
# Epoch 5/50
# 1211/1211 - 168s - 139ms/step - accuracy: 0.6848 - loss: 0.6236 - val_accuracy: 0.6887 - val_loss: 0.6207
# Epoch 6/50
# 1211/1211 - 168s - 138ms/step - accuracy: 0.6848 - loss: 0.6236 - val_accuracy: 0.6887 - val_loss: 0.6211
# Epoch 7/50
# 1211/1211 - 168s - 139ms/step - accuracy: 0.6848 - loss: 0.6235 - val_accuracy: 0.6887 - val_loss: 0.6202
# Epoch 8/50
# 1211/1211 - 168s - 138ms/step - accuracy: 0.6848 - loss: 0.6235 - val_accuracy: 0.6887 - val_loss: 0.6201
# Epoch 9/50
# 1211/1211 - 168s - 138ms/step - accuracy: 0.6848 - loss: 0.6235 - val_accuracy: 0.6887 - val_loss: 0.6202
# Epoch 10/50
# 1211/1211 - 168s - 138ms/step - accuracy: 0.6848 - loss: 0.6233 - val_accuracy: 0.6887 - val_loss: 0.6212
# Epoch 11/50
# 1211/1211 - 168s - 139ms/step - accuracy: 0.6848 - loss: 0.6236 - val_accuracy: 0.6887 - val_loss: 0.6205
# Epoch 12/50
# 1211/1211 - 168s - 139ms/step - accuracy: 0.6848 - loss: 0.6234 - val_accuracy: 0.6887 - val_loss: 0.6206
# Epoch 13/50
# 1211/1211 - 168s - 139ms/step - accuracy: 0.6848 - loss: 0.6234 - val_accuracy: 0.6887 - val_loss: 0.6201
# Epoch 14/50
# 1211/1211 - 168s - 139ms/step - accuracy: 0.6848 - loss: 0.6235 - val_accuracy: 0.6887 - val_loss: 0.6209
# Epoch 15/50
# 1211/1211 - 168s - 139ms/step - accuracy: 0.6848 - loss: 0.6234 - val_accuracy: 0.6887 - val_loss: 0.6203
# Epoch 16/50
# 1211/1211 - 168s - 139ms/step - accuracy: 0.6848 - loss: 0.6235 - val_accuracy: 0.6887 - val_loss: 0.6203
# Epoch 17/50
# 1211/1211 - 168s - 139ms/step - accuracy: 0.6848 - loss: 0.6235 - val_accuracy: 0.6887 - val_loss: 0.6202
# Epoch 18/50
# 1211/1211 - 168s - 139ms/step - accuracy: 0.6848 - loss: 0.6235 - val_accuracy: 0.6887 - val_loss: 0.6208
# Epoch 19/50
# 1211/1211 - 168s - 139ms/step - accuracy: 0.6848 - loss: 0.6235 - val_accuracy: 0.6887 - val_loss: 0.6205
# Epoch 20/50
# 1211/1211 - 168s - 139ms/step - accuracy: 0.6848 - loss: 0.6234 - val_accuracy: 0.6887 - val_loss: 0.6201
# Epoch 21/50
# 1211/1211 - 168s - 139ms/step - accuracy: 0.6848 - loss: 0.6234 - val_accuracy: 0.6887 - val_loss: 0.6201
# Epoch 22/50
# 1211/1211 - 168s - 139ms/step - accuracy: 0.6848 - loss: 0.6233 - val_accuracy: 0.6887 - val_loss: 0.6205
# Epoch 23/50
# 1211/1211 - 168s - 139ms/step - accuracy: 0.6848 - loss: 0.6234 - val_accuracy: 0.6887 - val_loss: 0.6202
# Epoch 24/50
# 1211/1211 - 168s - 139ms/step - accuracy: 0.6848 - loss: 0.6233 - val_accuracy: 0.6887 - val_loss: 0.6202
# Epoch 25/50
# 1211/1211 - 168s - 139ms/step - accuracy: 0.6848 - loss: 0.6233 - val_accuracy: 0.6887 - val_loss: 0.6204
# Epoch 26/50
# 1211/1211 - 168s - 139ms/step - accuracy: 0.6848 - loss: 0.6234 - val_accuracy: 0.6887 - val_loss: 0.6204
# Epoch 27/50
# 1211/1211 - 168s - 139ms/step - accuracy: 0.6848 - loss: 0.6233 - val_accuracy: 0.6887 - val_loss: 0.6201
# Epoch 28/50
# 1211/1211 - 168s - 139ms/step - accuracy: 0.6848 - loss: 0.6233 - val_accuracy: 0.6887 - val_loss: 0.6201
# Epoch 29/50
# 1211/1211 - 167s - 138ms/step - accuracy: 0.6848 - loss: 0.6233 - val_accuracy: 0.6887 - val_loss: 0.6201
# Epoch 30/50
# 1211/1211 - 167s - 138ms/step - accuracy: 0.6848 - loss: 0.6234 - val_accuracy: 0.6887 - val_loss: 0.6203
# Epoch 31/50
# 1211/1211 - 167s - 138ms/step - accuracy: 0.6848 - loss: 0.6234 - val_accuracy: 0.6887 - val_loss: 0.6202
# Epoch 32/50
# 1211/1211 - 167s - 138ms/step - accuracy: 0.6848 - loss: 0.6232 - val_accuracy: 0.6887 - val_loss: 0.6203
# Epoch 33/50
# 1211/1211 - 166s - 137ms/step - accuracy: 0.6848 - loss: 0.6233 - val_accuracy: 0.6887 - val_loss: 0.6202
# Epoch 34/50
# 1211/1211 - 166s - 137ms/step - accuracy: 0.6848 - loss: 0.6233 - val_accuracy: 0.6887 - val_loss: 0.6202
# Epoch 35/50
# 1211/1211 - 166s - 137ms/step - accuracy: 0.6848 - loss: 0.6233 - val_accuracy: 0.6887 - val_loss: 0.6201
# Epoch 36/50
# 1211/1211 - 167s - 137ms/step - accuracy: 0.6848 - loss: 0.6233 - val_accuracy: 0.6887 - val_loss: 0.6203
# Epoch 37/50
# 1211/1211 - 167s - 138ms/step - accuracy: 0.6848 - loss: 0.6233 - val_accuracy: 0.6887 - val_loss: 0.6208
# Epoch 38/50
# 1211/1211 - 167s - 138ms/step - accuracy: 0.6848 - loss: 0.6233 - val_accuracy: 0.6887 - val_loss: 0.6201
# Epoch 39/50
# 1211/1211 - 167s - 138ms/step - accuracy: 0.6848 - loss: 0.6233 - val_accuracy: 0.6887 - val_loss: 0.6202
# Epoch 40/50
# 1211/1211 - 167s - 138ms/step - accuracy: 0.6848 - loss: 0.6233 - val_accuracy: 0.6887 - val_loss: 0.6201
# Epoch 41/50
# 1211/1211 - 167s - 137ms/step - accuracy: 0.6848 - loss: 0.6232 - val_accuracy: 0.6887 - val_loss: 0.6202
# Epoch 42/50
# 1211/1211 - 167s - 138ms/step - accuracy: 0.6848 - loss: 0.6233 - val_accuracy: 0.6887 - val_loss: 0.6202
# Epoch 43/50
# 1211/1211 - 167s - 138ms/step - accuracy: 0.6848 - loss: 0.6232 - val_accuracy: 0.6887 - val_loss: 0.6206
# Epoch 44/50
# 1211/1211 - 167s - 138ms/step - accuracy: 0.6848 - loss: 0.6233 - val_accuracy: 0.6887 - val_loss: 0.6202
# Epoch 45/50
# 1211/1211 - 166s - 137ms/step - accuracy: 0.6848 - loss: 0.6233 - val_accuracy: 0.6887 - val_loss: 0.6203
# Epoch 46/50
# 1211/1211 - 166s - 137ms/step - accuracy: 0.6848 - loss: 0.6232 - val_accuracy: 0.6887 - val_loss: 0.6210
# Epoch 47/50
# 1211/1211 - 166s - 137ms/step - accuracy: 0.6848 - loss: 0.6233 - val_accuracy: 0.6887 - val_loss: 0.6201
# Epoch 48/50
# 1211/1211 - 166s - 137ms/step - accuracy: 0.6848 - loss: 0.6233 - val_accuracy: 0.6887 - val_loss: 0.6204
# Epoch 49/50
# 1211/1211 - 166s - 137ms/step - accuracy: 0.6848 - loss: 0.6233 - val_accuracy: 0.6887 - val_loss: 0.6206
# Epoch 50/50
# 1211/1211 - 166s - 137ms/step - accuracy: 0.6848 - loss: 0.6233 - val_accuracy: 0.6887 - val_loss: 0.6202
# Figure(1000x600)
# 379/379 ━━━━━━━━━━━━━━━━━━━━ 21s 53ms/step
# /usr/local/lib/python3.11/dist-packages/sklearn/metrics/_classification.py:1565: UndefinedMetricWarning: Precision is ill-defined and being set to 0.0 in labels with no predicted samples. Use `zero_division` parameter to control this behavior.
#   _warn_prf(average, modifier, f"{metric.capitalize()} is", len(result))
# /usr/local/lib/python3.11/dist-packages/sklearn/metrics/_classification.py:1565: UndefinedMetricWarning: Precision is ill-defined and being set to 0.0 in labels with no predicted samples. Use `zero_division` parameter to control this behavior.
#   _warn_prf(average, modifier, f"{metric.capitalize()} is", len(result))
# /usr/local/lib/python3.11/dist-packages/sklearn/metrics/_classification.py:1565: UndefinedMetricWarning: Precision is ill-defined and being set to 0.0 in labels with no predicted samples. Use `zero_division` parameter to control this behavior.
#   _warn_prf(average, modifier, f"{metric.capitalize()} is", len(result))
# Accuracy: 0.6800462504129501
# Classification Report:
#               precision    recall  f1-score   support
#
#         Safe       0.68      1.00      0.81      8234
#   Vulnerable       0.00      0.00      0.00      3874
#
#     accuracy                           0.68     12108
#    macro avg       0.34      0.50      0.40     12108
# weighted avg       0.46      0.68      0.55     12108
#
# WARNING:absl:You are saving your model as an HDF5 file via `model.save()` or `keras.saving.save_model(model)`. This file format is considered legacy. We recommend using instead the native Keras format, e.g. `model.save('my_model.keras')` or `keras.saving.save_model(model, 'my_model.keras')`.
# Model training completed and saved.


