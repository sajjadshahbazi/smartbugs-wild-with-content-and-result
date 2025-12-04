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
import matplotlib.pyplot as plt

duration_stat = {}
count = {}
output = {}
safe_count = 0
vul_count = 0
labels = []
fragment_contracts = []
dataframes_list = []
batch_size = 1000
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

ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), '..'))
CACHE_DIR = os.path.join(ROOT, 'vectorcollections02')

cache_path = os.path.join(CACHE_DIR, 'tokenized_fragments.pkl')
vulnerability_fd = open(os.path.join(ROOT, 'metadata', 'vulnerabilities.csv'), 'w', encoding='utf-8')

PATH = f"{ROOT}\\contracts\\"  # main data set
# PATH = f"{ROOT}\\contract\\"  # part of main data set
# PATH = f"{ROOT}\\contra\\"  # one smart contract

os.chdir(PATH)

final_df = pd.DataFrame(columns=['X', 'Y'])

# =========================================================
# تغییر ۱: اضافه کردن دو متغیر جهانی برای Word2Vec هر بچ
# =========================================================
BATCH_ALL_TOKENS = []           # همه توکن‌های این بچ
BATCH_WORD2VEC_MODEL = None     # مدل Word2Vec این بچ (فقط یک بار ساخته میشه)

# =========================================================
# تمام توابع تو — دقیقاً مثل قبل (بدون تغییر)
# =========================================================
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
        path_result = os.path.join(f"{ROOT}results", tool, output_name, contract_name, 'result.json')
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
                    'tools': {}, 'lines': set(), 'nb_vulnerabilities': 0
                }
            output[contract_name]['tools'][tool] = {
                'vulnerabilities': {}, 'categories': {}
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
                    if 'source_mapping' in result['elements'][0] and len(result['elements'][0]['source_mapping']['lines']) > 0:
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
    os.makedirs(cache_dir, exist_ok=True)
    for i in range(0, len(data), batch_size):
        batch = data[i:i + batch_size]
        filename = f"{file_prefix}_batch_{batch_index}_{i // batch_size}.pkl"
        filepath = os.path.join(cache_dir, filename)
        with open(filepath, 'wb') as f:
            pickle.dump(batch, f)
        print(f"Saved batch to {filepath}")

def extract_functions(code):
    functions = []
    function_pattern = re.compile(r'function\s+\w+\s*\(.*\)\s*(public|private|internal|external)*\s*(view|pure)*\s*(returns\s*\(.*\))?\s*{')
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
            normalized_tokens.append('VAR')
        elif token in ['}', '{', '(', ')', '[', ']', '.', ';', ',', '+', '-', '=', '!', '?', ':']:
            normalized_tokens.append(token)
        elif token.strip() == '':
            continue
        else:
            normalized_tokens.append(token)
    return normalized_tokens

def extract_functions_with_bodies(contract_code):
    functions = []
    function_pattern = re.compile(r'function\s+\w+\s*\(.*?\)\s*(public|private|internal|external)?\s*(view|pure)?\s*(returns\s*\(.*?\))?\s*{')
    lines = contract_code.splitlines()
    open_brackets = 0
    in_function = False
    function_body = []
    start_line = 0

    for i, line in enumerate(lines):
        if not in_function:
            match = function_pattern.search(line)
            if match:
                in_function = True
                start_line = i + 1
                function_body = [line]
                open_brackets = line.count('{') - line.count('}')
        else:
            function_body.append(line)
            open_brackets += line.count('{') - line.count('}')
            if open_brackets == 0:
                end_line = i + 1
                functions.append({
                    'function_body': '\n'.join(function_body),
                    'start_line': start_line,
                    'end_line': end_line,
                    'label': 0
                })
                in_function = False
    return functions

# =========================================================
# تغییر ۲: vectorize_tokens کاملاً جدید و بهینه
# =========================================================
def vectorize_tokens(tokens):
    global BATCH_WORD2VEC_MODEL
    if BATCH_WORD2VEC_MODEL is None:
        print(f"   Training Word2Vec on {len(BATCH_ALL_TOKENS)} token sequences in this batch...")
        BATCH_WORD2VEC_MODEL = Word2Vec(
            sentences=BATCH_ALL_TOKENS,
            vector_size=vector_length,
            window=5,
            min_count=1,
            workers=4,
            epochs=5
        )
        print(f"   Word2Vec trained with {len(BATCH_WORD2VEC_MODEL.wv)} unique tokens.")

    embeddings = [
        BATCH_WORD2VEC_MODEL.wv[word] if word in BATCH_WORD2VEC_MODEL.wv else np.zeros(vector_length)
        for word in tokens
    ]
    embeddings = embeddings[:sequence_length] + [np.zeros(vector_length)] * max(0, sequence_length - len(embeddings))
    return np.array(embeddings, dtype='float32')

def label_functions_by_vulnerable_lines(functions, vulnerable_lines):
    for func in functions:
        if any(func['start_line'] <= line <= func['end_line'] for line in vulnerable_lines):
            func['label'] = 1

# =========================================================
# تغییر ۳ و ۴: فقط در process_batch_with_categorization
# =========================================================
def process_batch_with_categorization(files, target_vulnerability, batch_size, batch_index):
    global BATCH_ALL_TOKENS, BATCH_WORD2VEC_MODEL
    BATCH_ALL_TOKENS = []           # ریست برای بچ جدید
    BATCH_WORD2VEC_MODEL = None     # ریست مدل

    X_sensitive_negative, Y_sensitive_negative = [], []
    X_vulnerable, Y_vulnerable = [], []
    X_safe, Y_safe = [], []
    max_function_length = 50

    sc_files = [f for f in files if f.endswith(".sol")]
    print(f"Batch {batch_index} — {len(sc_files)} contracts")

    # مرحله ۱: جمع‌آوری همه توکن‌ها
    for file in sc_files:
        with open(file, encoding="utf8") as f:
            contract_content = f.read()
        functions = extract_functions_with_bodies(contract_content)
        name = Path(file).stem
        _, vulnerable_lines = getResultVulnarable(name, target_vulnerability)
        label_functions_by_vulnerable_lines(functions, vulnerable_lines)
        for func in functions:
            fragments = PreProcessTools.get_fragments(func['function_body'])
            for fragment in fragments:
                if fragment.strip():
                    tokens = tokenize_solidity_code(fragment)
                    if tokens:
                        BATCH_ALL_TOKENS.append(tokens)

    # مرحله ۲: پردازش واقعی
    for file in sc_files:
        with open(file, encoding="utf8") as f:
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
                        vectors = vectorize_tokens(tokens)  # اینجا فقط یک بار مدل ساخته شده
                        func_vectors.extend(vectors)
            if func_vectors:
                padded_function = pad_sequences([func_vectors], maxlen=max_function_length, padding='post', dtype='float32')[0]
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

    # ذخیره دقیقاً مثل قبل
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
    print(f"Batch {batch_index} saved successfully.")

# =========================================================
# train_LSTM و main — دقیقاً مثل کد تو
# =========================================================
def train_LSTM():
    X, Y = load_batches(CACHE_DIR, file_extension=".pkl")
    print(f"Shape of X: {X.shape}")
    print(f"Shape of Y: {Y.shape}")
    print("Distribution in Y:", np.unique(Y, return_counts=True))

    X_train, X_test, Y_train, Y_test = train_test_split(X, Y, test_size=0.2, random_state=42)

    model = Sequential([
        Input(shape=(X_train.shape[1], X_train.shape[2])),
        Bidirectional(LSTM(128, return_sequences=True)),
        Bidirectional(LSTM(64)),
        Dense(1, activation='sigmoid')
    ])

    model.compile(optimizer=Adam(learning_rate=0.001), loss="binary_crossentropy", metrics=['accuracy'])
    early_stopping = EarlyStopping(monitor='val_loss', patience=10, restore_best_weights=True)

    history = model.fit(X_train, Y_train, epochs=50, batch_size=32, validation_split=0.2, callbacks=[early_stopping], verbose=2)

    plt.figure(figsize=(10, 6))
    plt.plot(history.history['accuracy'], label='train acc')
    plt.plot(history.history['val_accuracy'], label='val acc')
    plt.plot(history.history['loss'], label='train loss')
    plt.plot(history.history['val_loss'], label='val loss')
    plt.legend(); plt.grid(); plt.savefig("training_plot_lstm.png", dpi=300, bbox_inches='tight'); plt.show()

    Y_pred = (model.predict(X_test) > 0.5).astype("int32")
    print(f"Accuracy: {accuracy_score(Y_test, Y_pred)}")
    print(classification_report(Y_test, Y_pred, target_names=['Safe', 'Vulnerable']))
    model.save('final_LSTM_model.h5')

if __name__ == "__main__":
    files = [os.path.join(PATH, f) for f in os.listdir(PATH) if f.endswith(".sol")]
    print(f"Total files: {len(files)}")
    for batch_index, i in enumerate(range(0, len(files), batch_size)):
        batch_files = files[i:i + batch_size]
        print(f"Processing batch {batch_index} ({len(batch_files)} files)")
        process_batch_with_categorization(batch_files, target_vulner, batch_size, batch_index)


    # train_LSTM()



# Epoch 1/50
# I0000 00:00:1738240697.911710    7338 cuda_dnn.cc:529] Loaded cuDNN version 90300
# 1211/1211 - 23s - 19ms/step - accuracy: 0.7384 - loss: 0.5305 - val_accuracy: 0.7660 - val_loss: 0.4849
# Epoch 2/50
# 1211/1211 - 17s - 14ms/step - accuracy: 0.7723 - loss: 0.4746 - val_accuracy: 0.7799 - val_loss: 0.4494
# Epoch 3/50
# 1211/1211 - 17s - 14ms/step - accuracy: 0.7789 - loss: 0.4414 - val_accuracy: 0.7950 - val_loss: 0.4158
# Epoch 4/50
# 1211/1211 - 17s - 14ms/step - accuracy: 0.7913 - loss: 0.4173 - val_accuracy: 0.7981 - val_loss: 0.4137
# Epoch 5/50
# 1211/1211 - 17s - 14ms/step - accuracy: 0.7977 - loss: 0.4064 - val_accuracy: 0.8095 - val_loss: 0.3981
# Epoch 6/50
# 1211/1211 - 17s - 14ms/step - accuracy: 0.8006 - loss: 0.3990 - val_accuracy: 0.7916 - val_loss: 0.4069
# Epoch 7/50
# 1211/1211 - 17s - 14ms/step - accuracy: 0.8070 - loss: 0.3881 - val_accuracy: 0.8115 - val_loss: 0.3841
# Epoch 8/50
# 1211/1211 - 17s - 14ms/step - accuracy: 0.8119 - loss: 0.3806 - val_accuracy: 0.8172 - val_loss: 0.3744
# Epoch 9/50
# 1211/1211 - 17s - 14ms/step - accuracy: 0.8166 - loss: 0.3721 - val_accuracy: 0.8029 - val_loss: 0.3921
# Epoch 10/50
# 1211/1211 - 17s - 14ms/step - accuracy: 0.8184 - loss: 0.3681 - val_accuracy: 0.8173 - val_loss: 0.3714
# Epoch 11/50
# 1211/1211 - 17s - 14ms/step - accuracy: 0.8226 - loss: 0.3619 - val_accuracy: 0.8190 - val_loss: 0.3639
# Epoch 12/50
# 1211/1211 - 17s - 14ms/step - accuracy: 0.8291 - loss: 0.3532 - val_accuracy: 0.8224 - val_loss: 0.3621
# Epoch 13/50
# 1211/1211 - 17s - 14ms/step - accuracy: 0.8329 - loss: 0.3478 - val_accuracy: 0.8216 - val_loss: 0.3627
# Epoch 14/50
# 1211/1211 - 17s - 14ms/step - accuracy: 0.8365 - loss: 0.3424 - val_accuracy: 0.8298 - val_loss: 0.3546
# Epoch 15/50
# 1211/1211 - 17s - 14ms/step - accuracy: 0.8410 - loss: 0.3352 - val_accuracy: 0.8274 - val_loss: 0.3511
# Epoch 16/50
# 1211/1211 - 17s - 14ms/step - accuracy: 0.8428 - loss: 0.3297 - val_accuracy: 0.8311 - val_loss: 0.3485
# Epoch 17/50
# 1211/1211 - 17s - 14ms/step - accuracy: 0.8479 - loss: 0.3243 - val_accuracy: 0.8362 - val_loss: 0.3441
# Epoch 18/50
# 1211/1211 - 17s - 14ms/step - accuracy: 0.8502 - loss: 0.3175 - val_accuracy: 0.8385 - val_loss: 0.3398
# Epoch 19/50
# 1211/1211 - 17s - 14ms/step - accuracy: 0.8541 - loss: 0.3124 - val_accuracy: 0.8398 - val_loss: 0.3403
# Epoch 20/50
# 1211/1211 - 17s - 14ms/step - accuracy: 0.8592 - loss: 0.3057 - val_accuracy: 0.8416 - val_loss: 0.3405
# Epoch 21/50
# 1211/1211 - 17s - 14ms/step - accuracy: 0.8618 - loss: 0.3028 - val_accuracy: 0.8472 - val_loss: 0.3374
# Epoch 22/50
# 1211/1211 - 17s - 14ms/step - accuracy: 0.8668 - loss: 0.2947 - val_accuracy: 0.8391 - val_loss: 0.3503
# Epoch 23/50
# 1211/1211 - 17s - 14ms/step - accuracy: 0.8708 - loss: 0.2893 - val_accuracy: 0.8445 - val_loss: 0.3387
# Epoch 24/50
# 1211/1211 - 17s - 14ms/step - accuracy: 0.8729 - loss: 0.2852 - val_accuracy: 0.8463 - val_loss: 0.3358
# Epoch 25/50
# 1211/1211 - 17s - 14ms/step - accuracy: 0.8769 - loss: 0.2787 - val_accuracy: 0.8499 - val_loss: 0.3400
# Epoch 26/50
# 1211/1211 - 17s - 14ms/step - accuracy: 0.8781 - loss: 0.2731 - val_accuracy: 0.8513 - val_loss: 0.3274
# Epoch 27/50
# 1211/1211 - 17s - 14ms/step - accuracy: 0.8807 - loss: 0.2709 - val_accuracy: 0.8504 - val_loss: 0.3286
# Epoch 28/50
# 1211/1211 - 17s - 14ms/step - accuracy: 0.8850 - loss: 0.2634 - val_accuracy: 0.8508 - val_loss: 0.3377
# Epoch 29/50
# 1211/1211 - 17s - 14ms/step - accuracy: 0.8855 - loss: 0.2612 - val_accuracy: 0.8521 - val_loss: 0.3310
# Epoch 30/50
# 1211/1211 - 17s - 14ms/step - accuracy: 0.8889 - loss: 0.2566 - val_accuracy: 0.8508 - val_loss: 0.3344
# Epoch 31/50
# 1211/1211 - 17s - 14ms/step - accuracy: 0.8932 - loss: 0.2479 - val_accuracy: 0.8534 - val_loss: 0.3344
# Epoch 32/50
# 1211/1211 - 17s - 14ms/step - accuracy: 0.8943 - loss: 0.2468 - val_accuracy: 0.8538 - val_loss: 0.3359
# Epoch 33/50
# 1211/1211 - 17s - 14ms/step - accuracy: 0.8962 - loss: 0.2439 - val_accuracy: 0.8573 - val_loss: 0.3355
# Epoch 34/50
# 1211/1211 - 17s - 14ms/step - accuracy: 0.8991 - loss: 0.2385 - val_accuracy: 0.8579 - val_loss: 0.3381
# Epoch 35/50
# 1211/1211 - 17s - 14ms/step - accuracy: 0.9009 - loss: 0.2349 - val_accuracy: 0.8602 - val_loss: 0.3334
# Epoch 36/50
# 1211/1211 - 17s - 14ms/step - accuracy: 0.8995 - loss: 0.2373 - val_accuracy: 0.8586 - val_loss: 0.3344
# Plot saved to training_plot_lstm.png
# Figure(1000x600)
# 379/379 ━━━━━━━━━━━━━━━━━━━━ 2s 6ms/step
# Accuracy: 0.8472910472414932
# Classification Report:
#               precision    recall  f1-score   support
#
#         Safe       0.87      0.91      0.89      8300
#   Vulnerable       0.78      0.71      0.75      3808
#
#     accuracy                           0.85     12108
#    macro avg       0.83      0.81      0.82     12108
# weighted avg       0.84      0.85      0.85     12108
#
# WARNING:absl:You are saving your model as an HDF5 file via `model.save()` or `keras.saving.save_model(model)`. This file format is considered legacy. We recommend using instead the native Keras format, e.g. `model.save('my_model.keras')` or `keras.saving.save_model(model, 'my_model.keras')`.
# Training complete with LSTM.