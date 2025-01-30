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
from tensorflow.keras.layers import Conv2D, MaxPooling2D, UpSampling2D, concatenate, Flatten, Dense, Bidirectional, LSTM, Input
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
PATH = os.path.join(ROOT, 'contracts')  # Linux

# PATH = os.path.join(ROOT, 'contract') # linux
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


# def train_LSTM():
#     X, Y = load_batches(CACHE_DIR, file_extension=".pkl")
#     print(f"Shape of X: {X.shape}")  # باید (samples, max_function_length, vector_length) باشد
#     print(f"Shape of Y: {Y.shape}")  # باید (samples,) باشد
#     print("Distribution in Y:", np.unique(Y, return_counts=True))
#
#     # تقسیم داده‌ها به آموزش و تست
#     X_train, X_test, Y_train, Y_test = train_test_split(X, Y, test_size=0.2, random_state=42)
#     print("Distribution in Y_test:", np.unique(Y_test, return_counts=True))
#
#     model = Sequential([
#         Input(shape=(X_train.shape[1], X_train.shape[2])),
#         Bidirectional(LSTM(128, return_sequences=True)),
#         Bidirectional(LSTM(64)),
#         Dense(1, activation='sigmoid')
#     ])
#
#     model.compile(
#         optimizer=Adam(learning_rate=0.001),
#         loss="binary_crossentropy",
#         metrics=['accuracy']
#     )
#
#     early_stopping = EarlyStopping(
#         monitor='val_loss',
#         patience=10,
#         restore_best_weights=True
#     )
#
#     history = model.fit(
#         X_train, Y_train,
#         epochs=50,
#         batch_size=32,
#         validation_split=0.2,
#         callbacks=[early_stopping],  # اضافه کردن Early Stopping
#         verbose=2
#     )
#
#     plt.figure(figsize=(10, 6))
#
#     plt.plot(history.history['accuracy'], label='train acc', color='blue')
#     plt.plot(history.history['val_accuracy'], label='val acc', color='yellow')
#
#     plt.plot(history.history['loss'], label='train loss', color='red')
#     plt.plot(history.history['val_loss'], label='val loss', color='green')
#
#     plt.title('Model Accuracy and Loss')
#     plt.xlabel('Epochs')
#     plt.ylabel('Accuracy / Loss')
#     plt.legend(loc='best')
#     plt.grid()
#
#
#     output_image_path = "training_plot_lstm.png"
#     plt.savefig(output_image_path, dpi=300, bbox_inches='tight')
#     print(f"Plot saved to {output_image_path}")
#
#     plt.show()
#
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
#     model.save('final_LSTM_model.h5')
#     print("Training complete with LSTM.")


def build_unet(input_shape):
    """
    ساختار U-Net برای استخراج ویژگی‌ها
    """
    inputs = Input(input_shape)

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

    outputs = Conv2D(1, (1, 1), activation='sigmoid')(conv5)

    return Model(inputs, outputs)


def prepare_data_for_unet(X, target_shape=(64, 64)):
    """
    تبدیل داده‌های سه‌بعدی به ماتریس‌های دوبعدی برای U-Net
    """
    n_samples = X.shape[0]
    total_elements = target_shape[0] * target_shape[1]

    reshaped_data = []
    for sample in X:
        flat_sample = sample.flatten()

        if len(flat_sample) > total_elements:
            flat_sample = flat_sample[:total_elements]
        else:
            flat_sample = np.pad(flat_sample, (0, total_elements - len(flat_sample)), mode='constant')

        reshaped_data.append(flat_sample.reshape(target_shape))

    reshaped_data = np.array(reshaped_data).reshape(n_samples, target_shape[0], target_shape[1], 1)
    return reshaped_data


def build_unet(input_shape):
    """
    ساختار U-Net
    """
    inputs = Input(input_shape)

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

    outputs = Conv2D(1, (1, 1), activation='sigmoid')(conv5)

    return Model(inputs, outputs)


def build_unet_lstm(input_shape_unet, input_shape_lstm):
    """
    ترکیب U-Net و LSTM
    """
    # ساخت مدل U-Net
    unet_model = build_unet(input_shape_unet)

    # Flatten کردن خروجی U-Net
    unet_output = Flatten()(unet_model.output)

    # LSTM
    lstm_input = Input(shape=input_shape_lstm)
    lstm_output = Bidirectional(LSTM(128, return_sequences=True))(lstm_input)
    lstm_output = Bidirectional(LSTM(64))(lstm_output)

    # ادغام U-Net و LSTM
    combined_features = concatenate([unet_output, lstm_output])

    # لایه‌های Dense برای طبقه‌بندی
    dense1 = Dense(128, activation='relu')(combined_features)
    dense2 = Dense(64, activation='relu')(dense1)
    outputs = Dense(1, activation='sigmoid')(dense2)

    return Model(inputs=[unet_model.input, lstm_input], outputs=outputs)



def train_unet_lstm():
    # بارگذاری داده‌ها
    X, Y = load_batches(CACHE_DIR, file_extension=".pkl")

    # آماده‌سازی داده‌ها برای U-Net
    X_unet = prepare_data_for_unet(X, target_shape=(64, 64))

    # تقسیم داده‌ها به آموزش و تست
    X_train_lstm, X_test_lstm, X_train_unet, X_test_unet, Y_train, Y_test = train_test_split(
        X, X_unet, Y, test_size=0.2, random_state=42
    )

    # ساخت مدل
    model = build_unet_lstm((64, 64, 1), (X.shape[1], X.shape[2]))

    # کامپایل مدل
    model.compile(optimizer=Adam(learning_rate=0.001), loss="binary_crossentropy", metrics=['accuracy'])

    # Callback برای توقف زودهنگام
    early_stopping = EarlyStopping(monitor='val_loss', patience=10, restore_best_weights=True)

    # آموزش مدل
    history = model.fit(
        [X_train_unet, X_train_lstm], Y_train,
        epochs=50, batch_size=32, validation_split=0.2, verbose=2,
        callbacks=[early_stopping]
    )

    # نمایش گراف‌های دقت و خطا
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

    # پیش‌بینی و ارزیابی
    Y_pred = (model.predict([X_test_unet, X_test_lstm]) > 0.5).astype("int32")
    accuracy = accuracy_score(Y_test, Y_pred)
    report = classification_report(Y_test, Y_pred, target_names=['Safe', 'Vulnerable'], labels=[0, 1])

    print(f"Accuracy: {accuracy}")
    print("Classification Report:")
    print(report)

    # ذخیره مدل
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
# Epoch 1/50
# I0000 00:00:1738232193.796868    6361 cuda_dnn.cc:529] Loaded cuDNN version 90300
# 1211/1211 - 56s - 46ms/step - accuracy: 0.6884 - loss: 0.6208 - val_accuracy: 0.6814 - val_loss: 0.6196
# Epoch 2/50
# 1211/1211 - 45s - 37ms/step - accuracy: 0.7127 - loss: 0.5654 - val_accuracy: 0.7270 - val_loss: 0.5297
# Epoch 3/50
# 1211/1211 - 45s - 37ms/step - accuracy: 0.7193 - loss: 0.5404 - val_accuracy: 0.6814 - val_loss: 0.5892
# Epoch 4/50
# 1211/1211 - 45s - 37ms/step - accuracy: 0.7225 - loss: 0.5358 - val_accuracy: 0.7220 - val_loss: 0.5218
# Epoch 5/50
# 1211/1211 - 45s - 37ms/step - accuracy: 0.7289 - loss: 0.5170 - val_accuracy: 0.7220 - val_loss: 0.5086
# Epoch 6/50
# 1211/1211 - 45s - 37ms/step - accuracy: 0.7616 - loss: 0.4884 - val_accuracy: 0.7673 - val_loss: 0.4702
# Epoch 7/50
# 1211/1211 - 45s - 37ms/step - accuracy: 0.7796 - loss: 0.4530 - val_accuracy: 0.7750 - val_loss: 0.4469
# Epoch 8/50
# 1211/1211 - 45s - 37ms/step - accuracy: 0.7868 - loss: 0.4336 - val_accuracy: 0.7907 - val_loss: 0.4243
# Epoch 9/50
# 1211/1211 - 44s - 37ms/step - accuracy: 0.7935 - loss: 0.4198 - val_accuracy: 0.7985 - val_loss: 0.4165
# Epoch 10/50
# 1211/1211 - 44s - 37ms/step - accuracy: 0.8002 - loss: 0.4085 - val_accuracy: 0.8005 - val_loss: 0.4106
# Epoch 11/50
# 1211/1211 - 45s - 37ms/step - accuracy: 0.8043 - loss: 0.3994 - val_accuracy: 0.7991 - val_loss: 0.4088
# Epoch 12/50
# 1211/1211 - 45s - 37ms/step - accuracy: 0.8108 - loss: 0.3920 - val_accuracy: 0.8098 - val_loss: 0.4012
# Epoch 13/50
# 1211/1211 - 45s - 37ms/step - accuracy: 0.8132 - loss: 0.3860 - val_accuracy: 0.8031 - val_loss: 0.4023
# Epoch 14/50
# 1211/1211 - 44s - 37ms/step - accuracy: 0.8168 - loss: 0.3816 - val_accuracy: 0.8098 - val_loss: 0.3990
# Epoch 15/50
# 1211/1211 - 45s - 37ms/step - accuracy: 0.8191 - loss: 0.3771 - val_accuracy: 0.8126 - val_loss: 0.3927
# Epoch 16/50
# 1211/1211 - 44s - 37ms/step - accuracy: 0.8241 - loss: 0.3727 - val_accuracy: 0.8111 - val_loss: 0.3926
# Epoch 17/50
# 1211/1211 - 44s - 37ms/step - accuracy: 0.8246 - loss: 0.3693 - val_accuracy: 0.8126 - val_loss: 0.3995
# Epoch 18/50
# 1211/1211 - 44s - 37ms/step - accuracy: 0.8279 - loss: 0.3652 - val_accuracy: 0.8008 - val_loss: 0.3985
# Epoch 19/50
# 1211/1211 - 44s - 37ms/step - accuracy: 0.8287 - loss: 0.3622 - val_accuracy: 0.8199 - val_loss: 0.3871
# Epoch 20/50
# 1211/1211 - 44s - 37ms/step - accuracy: 0.8315 - loss: 0.3575 - val_accuracy: 0.8159 - val_loss: 0.3851
# Epoch 21/50
# 1211/1211 - 44s - 37ms/step - accuracy: 0.8344 - loss: 0.3548 - val_accuracy: 0.8136 - val_loss: 0.4066
# Epoch 22/50
# 1211/1211 - 44s - 36ms/step - accuracy: 0.8356 - loss: 0.3521 - val_accuracy: 0.8156 - val_loss: 0.3871
# Epoch 23/50
# 1211/1211 - 44s - 37ms/step - accuracy: 0.8375 - loss: 0.3497 - val_accuracy: 0.8167 - val_loss: 0.3848
# Epoch 24/50
# 1211/1211 - 44s - 37ms/step - accuracy: 0.8402 - loss: 0.3476 - val_accuracy: 0.8192 - val_loss: 0.3892
# Epoch 25/50
# 1211/1211 - 44s - 37ms/step - accuracy: 0.8401 - loss: 0.3452 - val_accuracy: 0.8171 - val_loss: 0.3907
# Epoch 26/50
# 1211/1211 - 44s - 37ms/step - accuracy: 0.8414 - loss: 0.3425 - val_accuracy: 0.8237 - val_loss: 0.3848
# Epoch 27/50
# 1211/1211 - 45s - 37ms/step - accuracy: 0.8427 - loss: 0.3403 - val_accuracy: 0.8219 - val_loss: 0.3857
# Epoch 28/50
# 1211/1211 - 44s - 37ms/step - accuracy: 0.8438 - loss: 0.3382 - val_accuracy: 0.8185 - val_loss: 0.3886
# Epoch 29/50
# 1211/1211 - 44s - 37ms/step - accuracy: 0.8439 - loss: 0.3369 - val_accuracy: 0.8193 - val_loss: 0.3981
# Epoch 30/50
# 1211/1211 - 44s - 37ms/step - accuracy: 0.8455 - loss: 0.3357 - val_accuracy: 0.8233 - val_loss: 0.3858
# Epoch 31/50
# 1211/1211 - 45s - 37ms/step - accuracy: 0.8474 - loss: 0.3327 - val_accuracy: 0.8242 - val_loss: 0.3882
# Epoch 32/50
# 1211/1211 - 45s - 37ms/step - accuracy: 0.8489 - loss: 0.3322 - val_accuracy: 0.8256 - val_loss: 0.3884
# Epoch 33/50
# 1211/1211 - 44s - 37ms/step - accuracy: 0.8496 - loss: 0.3311 - val_accuracy: 0.8204 - val_loss: 0.3932
# Figure(1000x600)
# 379/379 ━━━━━━━━━━━━━━━━━━━━ 6s 14ms/step
# Accuracy: 0.821192599933928
# Classification Report:
#               precision    recall  f1-score   support
#
#         Safe       0.85      0.90      0.87      8300
#   Vulnerable       0.75      0.64      0.69      3808
#
#     accuracy                           0.82     12108
#    macro avg       0.80      0.77      0.78     12108
# weighted avg       0.82      0.82      0.82     12108
