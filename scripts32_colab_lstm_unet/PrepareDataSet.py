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
from tensorflow.keras.layers import Conv2D, Conv1D, LeakyReLU, UpSampling1D, GlobalAveragePooling1D, Bidirectional, concatenate, Cropping2D, MaxPooling2D, MaxPooling1D, UpSampling2D, concatenate, Flatten, Dense, Bidirectional, LSTM, Input, Reshape, BatchNormalization, Reshape
from tensorflow.keras.models import Model
from tensorflow.keras import layers, models
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.callbacks import EarlyStopping
import matplotlib.pyplot as plt
from sklearn.metrics import classification_report, accuracy_score




EPOCHS = 50
BATCH_SIZE = 32
LEARNING_RATE = 1e-3
PATIENCE = 10
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

def load_vectors(cache_dir, ext='.pkl'):
    X_batches, Y_batches = [], []
    for fn in os.listdir(cache_dir):
        if fn.endswith(ext):
            with open(os.path.join(cache_dir, fn), 'rb') as f:
                Xb, Yb = pickle.load(f)
                X_batches.append(Xb)
                Y_batches.append(Yb)
    X = np.vstack(X_batches)
    Y = np.hstack(Y_batches)
    return X, Y


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





def pad_to_multiple_of_four(X):
    """
    Pads the time dimension of X to the next multiple of 4 (for two 2x pool-upsampling).
    """
    seq_len = X.shape[1]
    if seq_len % 4 != 0:
        new_len = ((seq_len + 3) // 4) * 4
        pad_amount = new_len - seq_len
        # pad only on time axis at the end
        X = np.pad(X, ((0, 0), (0, pad_amount), (0, 0)), mode='constant')
    return X


def build_unet_lstm_model(seq_len, embed_dim):
    inp = Input(shape=(seq_len, embed_dim), name='input')
    # UNet branch (1D)
    c1 = Conv1D(64, 3, padding='same', activation='relu')(inp)
    p1 = MaxPooling1D(2)(c1)
    c2 = Conv1D(128, 3, padding='same', activation='relu')(p1)
    p2 = MaxPooling1D(2)(c2)
    c3 = Conv1D(256, 3, padding='same', activation='relu')(p2)
    u1 = UpSampling1D(2)(c3)
    m1 = concatenate([u1, c2])
    c4 = Conv1D(128, 3, padding='same', activation='relu')(m1)
    u2 = UpSampling1D(2)(c4)
    m2 = concatenate([u2, c1])
    c5 = Conv1D(64, 3, padding='same', activation='relu')(m2)
    unet_feat = GlobalAveragePooling1D(name='unet_gap')(c5)

    # LSTM branch
    l1 = Bidirectional(LSTM(128, return_sequences=True))(inp)
    l2 = Bidirectional(LSTM(64))(l1)

    # Combine branches
    merged = concatenate([unet_feat, l2], name='concat')
    d1 = Dense(64, activation='relu')(merged)
    drop = Dropout(0.5)(d1)
    out = Dense(1, activation='sigmoid', name='output')(drop)

    model = Model(inp, out, name='UNet_LSTM')
    model.compile(optimizer=Adam(LEARNING_RATE), loss='binary_crossentropy', metrics=['accuracy'])
    return model


if __name__ == '__main__':
    # Load data
    X, Y = load_vectors(CACHE_DIR)
    # Pad time dimension so that it is divisible by 4 (for exact pool/up steps)
    X = pad_to_multiple_of_four(X)
    print(f'Dataset shapes after padding: X={X.shape}, Y={Y.shape}')
    SEQ_LEN, EMBED_DIM = X.shape[1], X.shape[2]

    # Train/test split
    X_train, X_test, Y_train, Y_test = train_test_split(X, Y, test_size=0.2, random_state=42)

    # Build model
    model = build_unet_lstm_model(SEQ_LEN, EMBED_DIM)
    model.summary()

    # Callbacks
    early = EarlyStopping(monitor='val_loss', patience=PATIENCE, restore_best_weights=True)

    # Training
    history = model.fit(
        X_train, Y_train,
        validation_split=0.2,
        epochs=EPOCHS,
        batch_size=BATCH_SIZE,
        callbacks=[early],
        verbose=2
    )

    # Plot metrics
    plt.figure(figsize=(10, 6))
    plt.plot(history.history['accuracy'], label='train_acc')
    plt.plot(history.history['val_accuracy'], label='val_acc')
    plt.plot(history.history['loss'], label='train_loss')
    plt.plot(history.history['val_loss'], label='val_loss')
    plt.title('UNet+LSTM Accuracy and Loss')
    plt.xlabel('Epochs')
    plt.ylabel('Value')
    plt.legend()
    plt.grid()
    plt.savefig('training_plot_unet_lstm.png', dpi=300, bbox_inches='tight')
    plt.show()

    # Evaluation
    Y_pred = (model.predict(X_test) > 0.5).astype(int)
    acc = accuracy_score(Y_test, Y_pred)
    report = classification_report(Y_test, Y_pred, target_names=['Safe', 'Vulnerable'])
    print(f'UNet+LSTM Test Accuracy: {acc:.4f}')
    print('Classification Report:')
    print(report)

    # Save model
    model.save('final_unet_lstm_model.keras')
    print('UNet+LSTM training complete.')


#     //Model: "UNet_LSTM"
# ┏━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━┓
# ┃ Layer (type)        ┃ Output Shape      ┃    Param # ┃ Connected to      ┃
# ┡━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━┩
# │ input (InputLayer)  │ (None, 52, 300)   │          0 │ -                 │
# ├─────────────────────┼───────────────────┼────────────┼───────────────────┤
# │ conv1d (Conv1D)     │ (None, 52, 64)    │     57,664 │ input[0][0]       │
# ├─────────────────────┼───────────────────┼────────────┼───────────────────┤
# │ max_pooling1d       │ (None, 26, 64)    │          0 │ conv1d[0][0]      │
# │ (MaxPooling1D)      │                   │            │                   │
# ├─────────────────────┼───────────────────┼────────────┼───────────────────┤
# │ conv1d_1 (Conv1D)   │ (None, 26, 128)   │     24,704 │ max_pooling1d[0]… │
# ├─────────────────────┼───────────────────┼────────────┼───────────────────┤
# │ max_pooling1d_1     │ (None, 13, 128)   │          0 │ conv1d_1[0][0]    │
# │ (MaxPooling1D)      │                   │            │                   │
# ├─────────────────────┼───────────────────┼────────────┼───────────────────┤
# │ conv1d_2 (Conv1D)   │ (None, 13, 256)   │     98,560 │ max_pooling1d_1[… │
# ├─────────────────────┼───────────────────┼────────────┼───────────────────┤
# │ up_sampling1d       │ (None, 26, 256)   │          0 │ conv1d_2[0][0]    │
# │ (UpSampling1D)      │                   │            │                   │
# ├─────────────────────┼───────────────────┼────────────┼───────────────────┤
# │ concatenate         │ (None, 26, 384)   │          0 │ up_sampling1d[0]… │
# │ (Concatenate)       │                   │            │ conv1d_1[0][0]    │
# ├─────────────────────┼───────────────────┼────────────┼───────────────────┤
# │ conv1d_3 (Conv1D)   │ (None, 26, 128)   │    147,584 │ concatenate[0][0] │
# ├─────────────────────┼───────────────────┼────────────┼───────────────────┤
# │ up_sampling1d_1     │ (None, 52, 128)   │          0 │ conv1d_3[0][0]    │
# │ (UpSampling1D)      │                   │            │                   │
# ├─────────────────────┼───────────────────┼────────────┼───────────────────┤
# │ concatenate_1       │ (None, 52, 192)   │          0 │ up_sampling1d_1[… │
# │ (Concatenate)       │                   │            │ conv1d[0][0]      │
# ├─────────────────────┼───────────────────┼────────────┼───────────────────┤
# │ conv1d_4 (Conv1D)   │ (None, 52, 64)    │     36,928 │ concatenate_1[0]… │
# ├─────────────────────┼───────────────────┼────────────┼───────────────────┤
# │ bidirectional       │ (None, 52, 256)   │    439,296 │ input[0][0]       │
# │ (Bidirectional)     │                   │            │                   │
# ├─────────────────────┼───────────────────┼────────────┼───────────────────┤
# │ unet_gap            │ (None, 64)        │          0 │ conv1d_4[0][0]    │
# │ (GlobalAveragePool… │                   │            │                   │
# ├─────────────────────┼───────────────────┼────────────┼───────────────────┤
# │ bidirectional_1     │ (None, 128)       │    164,352 │ bidirectional[0]… │
# │ (Bidirectional)     │                   │            │                   │
# ├─────────────────────┼───────────────────┼────────────┼───────────────────┤
# │ concat              │ (None, 192)       │          0 │ unet_gap[0][0],   │
# │ (Concatenate)       │                   │            │ bidirectional_1[… │
# ├─────────────────────┼───────────────────┼────────────┼───────────────────┤
# │ dense (Dense)       │ (None, 64)        │     12,352 │ concat[0][0]      │
# ├─────────────────────┼───────────────────┼────────────┼───────────────────┤
# │ dropout (Dropout)   │ (None, 64)        │          0 │ dense[0][0]       │
# ├─────────────────────┼───────────────────┼────────────┼───────────────────┤
# │ output (Dense)      │ (None, 1)         │         65 │ dropout[0][0]     │
# └─────────────────────┴───────────────────┴────────────┴───────────────────┘
#  Total params: 981,505 (3.74 MB)
#  Trainable params: 981,505 (3.74 MB)
#  Non-trainable params: 0 (0.00 B)
# Epoch 1/50
# I0000 00:00:1745695889.985884   28093 cuda_dnn.cc:529] Loaded cuDNN version 90300
# 1211/1211 - 33s - 27ms/step - accuracy: 0.7440 - loss: 0.5247 - val_accuracy: 0.7803 - val_loss: 0.4705
# Epoch 2/50
# 1211/1211 - 23s - 19ms/step - accuracy: 0.7859 - loss: 0.4513 - val_accuracy: 0.7901 - val_loss: 0.4396
# Epoch 3/50
# 1211/1211 - 23s - 19ms/step - accuracy: 0.7925 - loss: 0.4131 - val_accuracy: 0.8033 - val_loss: 0.3927
# Epoch 4/50
# 1211/1211 - 23s - 19ms/step - accuracy: 0.8073 - loss: 0.3860 - val_accuracy: 0.8154 - val_loss: 0.3801
# Epoch 5/50
# 1211/1211 - 23s - 19ms/step - accuracy: 0.8197 - loss: 0.3693 - val_accuracy: 0.8193 - val_loss: 0.3683
# Epoch 6/50
# 1211/1211 - 23s - 19ms/step - accuracy: 0.8314 - loss: 0.3522 - val_accuracy: 0.8263 - val_loss: 0.3649
# Epoch 7/50
# 1211/1211 - 23s - 19ms/step - accuracy: 0.8382 - loss: 0.3406 - val_accuracy: 0.8348 - val_loss: 0.3538
# Epoch 8/50
# 1211/1211 - 23s - 19ms/step - accuracy: 0.8450 - loss: 0.3290 - val_accuracy: 0.8334 - val_loss: 0.3532
# Epoch 9/50
# 1211/1211 - 23s - 19ms/step - accuracy: 0.8551 - loss: 0.3181 - val_accuracy: 0.8373 - val_loss: 0.3540
# Epoch 10/50
# 1211/1211 - 23s - 19ms/step - accuracy: 0.8606 - loss: 0.3065 - val_accuracy: 0.8464 - val_loss: 0.3428
# Epoch 11/50
# 1211/1211 - 23s - 19ms/step - accuracy: 0.8656 - loss: 0.2975 - val_accuracy: 0.8454 - val_loss: 0.3492
# Epoch 12/50
# 1211/1211 - 23s - 19ms/step - accuracy: 0.8709 - loss: 0.2887 - val_accuracy: 0.8427 - val_loss: 0.3724
# Epoch 13/50
# 1211/1211 - 23s - 19ms/step - accuracy: 0.8774 - loss: 0.2770 - val_accuracy: 0.8434 - val_loss: 0.3469
# Epoch 14/50
# 1211/1211 - 23s - 19ms/step - accuracy: 0.8799 - loss: 0.2726 - val_accuracy: 0.8495 - val_loss: 0.3434
# Epoch 15/50
# 1211/1211 - 23s - 19ms/step - accuracy: 0.8841 - loss: 0.2624 - val_accuracy: 0.8538 - val_loss: 0.3721
# Epoch 16/50
# 1211/1211 - 23s - 19ms/step - accuracy: 0.8878 - loss: 0.2554 - val_accuracy: 0.8495 - val_loss: 0.3600
# Epoch 17/50
# 1211/1211 - 23s - 19ms/step - accuracy: 0.8905 - loss: 0.2511 - val_accuracy: 0.8546 - val_loss: 0.3624
# Epoch 18/50
# 1211/1211 - 23s - 19ms/step - accuracy: 0.8948 - loss: 0.2426 - val_accuracy: 0.8580 - val_loss: 0.3518
# Epoch 19/50
# 1211/1211 - 23s - 19ms/step - accuracy: 0.8974 - loss: 0.2385 - val_accuracy: 0.8534 - val_loss: 0.3734
# Epoch 20/50
# 1211/1211 - 23s - 19ms/step - accuracy: 0.8996 - loss: 0.2335 - val_accuracy: 0.8576 - val_loss: 0.3775
# Figure(1000x600)
# 379/379 ━━━━━━━━━━━━━━━━━━━━ 3s 7ms/step
# UNet+LSTM Test Accuracy: 0.8492
# Classification Report:
#               precision    recall  f1-score   support
#
#         Safe       0.89      0.90      0.89      8308
#   Vulnerable       0.77      0.75      0.76      3800
#
#     accuracy                           0.85     12108
#    macro avg       0.83      0.82      0.82     12108
# weighted avg       0.85      0.85      0.85     12108
#
# UNet+LSTM training complete.
