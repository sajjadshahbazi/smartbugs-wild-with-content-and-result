import json
import re
import os
from pathlib import Path
from imblearn.over_sampling import SMOTE
import pandas as pd
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.utils import Sequence
from tensorflow.keras.layers import BatchNormalization
from tensorflow.keras.layers import InputLayer

import sys
from gensim.models import Word2Vec
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

from tensorflow.keras.layers import Conv2D, MaxPooling2D, UpSampling2D, concatenate, Flatten
from tensorflow.keras.layers import GlobalAveragePooling2D
from tensorflow.keras.models import Model
from tensorflow.keras.models import load_model, Model as KerasModel

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

sequence_length = 100

co_occurrence_window = 3

vulnerability_mapping = {}

tools = ['mythril', 'slither', 'osiris', 'smartcheck', 'manticore', 'maian', 'securify',
         'honeybadger']

target_vulnerability_integer_overflow = 'Integer Overflow'
target_vulnerability_reentrancy = 'Reentrancy'
target_vulnerability_transaction_order_dependence = 'Transaction order dependence'
target_vulnerability_timestamp_dependency = 'timestamp'
target_vulnerability_callstack_depth_attack = 'Depth Attack'
target_vulnerability_integer_underflow = 'Integer Underflow'

target_vulner = target_vulnerability_reentrancy

ROOT = '/content/smartbugs-wild-with-content-and-result'
CACHE_DIR = os.path.join(ROOT, 'vectorcollections')

CACHE_DIR_UNET = os.path.join(ROOT, 'vectorcollections_img')

cache_path = os.path.join(CACHE_DIR, 'tokenized_fragments.pkl')
vulnerability_fd = open(os.path.join(ROOT, 'metadata', 'vulnerabilities.csv'), 'w', encoding='utf-8')

PATH = os.path.join(ROOT, 'contracts')
os.chdir(PATH)

final_df = pd.DataFrame(columns=['X', 'Y'])


def focal_loss(alpha=0.25, gamma=2.0):
    def loss(y_true, y_pred):
        epsilon = K.epsilon()
        y_pred = K.clip(y_pred, epsilon, 1. - epsilon)
        pt = y_true * y_pred + (1 - y_true) * (1 - y_pred)
        return -K.mean(alpha * K.pow(1. - pt, gamma) * K.log(pt))
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
        path_result = os.path.join(f"{ROOT}\\results\\", tool, output_name, contract_name, 'result.json')
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
    function_pattern = re.compile(
        r'function\s+\w+\s*\(.*?\)\s*(public|private|internal|external)?\s*(view|pure)?\s*(returns\s*\(.*?\))?\s*{')
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
            open_brackets += line.count('{')
            open_brackets -= line.count('}')
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


def vectorize_tokens(tokens):
    word2vec_model = Word2Vec(sentences=[tokens], vector_size=vector_length, window=5, min_count=1, workers=4)
    embeddings = [
        word2vec_model.wv[word] if word in word2vec_model.wv else np.zeros(vector_length)
        for word in tokens
    ]
    embeddings = embeddings[:sequence_length] + [np.zeros(vector_length)] * max(0, sequence_length - len(embeddings))
    return np.array(embeddings, dtype='float32')


def create_attention_map(embedding_matrix, real_token_count, window=co_occurrence_window):
    norms = np.linalg.norm(embedding_matrix, axis=1, keepdims=True)
    norms[norms == 0] = 1e-10
    normalized = embedding_matrix / norms
    similarity_matrix = np.dot(normalized, normalized.T)

    seq_len = embedding_matrix.shape[0]
    co_matrix = np.zeros((seq_len, seq_len), dtype='float32')
    limit = min(real_token_count, seq_len)
    for idx in range(limit):
        for w in range(1, window + 1):
            if idx + w < limit:
                co_matrix[idx][idx + w] = 1.0
                co_matrix[idx + w][idx] = 1.0

    attention_map = similarity_matrix * co_matrix
    attention_map = attention_map.reshape(seq_len, seq_len, 1)
    return attention_map.astype('float32')


def label_functions_by_vulnerable_lines(functions, vulnerable_lines):
    for func in functions:
        if any(func['start_line'] <= line <= func['end_line'] for line in vulnerable_lines):
            func['label'] = 1


def process_batch_with_categorization(files, target_vulnerability, batch_size, batch_index):
    X_sensitive_negative, Y_sensitive_negative = [], []
    X_vulnerable, Y_vulnerable = [], []
    X_safe, Y_safe = [], []

    max_function_length = 100

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

                all_tokens = []
                for fragment in fragments:
                    if fragment.strip():
                        tokens = tokenize_solidity_code(fragment)
                        if tokens:
                            all_tokens.extend(tokens)

                if all_tokens:
                    func_vectors = vectorize_tokens(all_tokens)
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


def load_batches_by_prefix(folder, prefix, file_extension=".pkl"):
    X_batches, Y_batches = [], []
    matched_files = sorted([
        f for f in os.listdir(folder)
        if f.endswith(file_extension) and f.startswith(prefix)
    ])
    for file in matched_files:
        with open(os.path.join(folder, file), 'rb') as f:
            X, Y = pickle.load(f)
            X_batches.append(X)
            Y_batches.append(Y)
    return np.vstack(X_batches), np.hstack(Y_batches)


def process_batch_with_categorization_for_unet(files, target_vulnerability, batch_size, batch_index):
    X_sensitive_negative_emb, X_sensitive_negative_att, Y_sensitive_negative = [], [], []
    X_vulnerable_emb, X_vulnerable_att, Y_vulnerable = [], [], []
    X_safe_emb, X_safe_att, Y_safe = [], [], []

    max_function_length = 100

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

                all_tokens = []
                for fragment in fragments:
                    if fragment.strip():
                        tokens = tokenize_solidity_code(fragment)
                        if tokens:
                            all_tokens.extend(tokens)

                if all_tokens:
                    func_vectors = vectorize_tokens(all_tokens)
                    padded_function = pad_sequences(
                        [func_vectors], maxlen=max_function_length, padding='post', dtype='float32'
                    )[0]

                    real_token_count = min(len(all_tokens), sequence_length)
                    att_map = create_attention_map(padded_function, real_token_count)

                    if label == 1:
                        X_vulnerable_emb.append(padded_function)
                        X_vulnerable_att.append(att_map)
                        Y_vulnerable.append(label)
                    else:
                        if contains_sensitive_operator(func['function_body']):
                            X_sensitive_negative_emb.append(padded_function)
                            X_sensitive_negative_att.append(att_map)
                            Y_sensitive_negative.append(label)
                        else:
                            X_safe_emb.append(padded_function)
                            X_safe_att.append(att_map)
                            Y_safe.append(label)

    def _to_arrays(x_emb, x_att, y):
        return (
            np.array(x_emb, dtype='float32'),
            np.array(x_att, dtype='float32'),
            np.array(y, dtype='int32')
        )

    X_vulnerable_emb, X_vulnerable_att, Y_vulnerable = _to_arrays(X_vulnerable_emb, X_vulnerable_att, Y_vulnerable)
    X_sensitive_negative_emb, X_sensitive_negative_att, Y_sensitive_negative = _to_arrays(
        X_sensitive_negative_emb, X_sensitive_negative_att, Y_sensitive_negative)
    X_safe_emb, X_safe_att, Y_safe = _to_arrays(X_safe_emb, X_safe_att, Y_safe)

    os.makedirs(CACHE_DIR_UNET, exist_ok=True)

    with open(os.path.join(CACHE_DIR_UNET, f"emb_vulnerable_batch_{batch_index}.pkl"), 'wb') as f:
        pickle.dump((X_vulnerable_emb, Y_vulnerable), f)
    with open(os.path.join(CACHE_DIR_UNET, f"emb_sensitive_negative_batch_{batch_index}.pkl"), 'wb') as f:
        pickle.dump((X_sensitive_negative_emb, Y_sensitive_negative), f)
    with open(os.path.join(CACHE_DIR_UNET, f"emb_safe_batch_{batch_index}.pkl"), 'wb') as f:
        pickle.dump((X_safe_emb, Y_safe), f)

    with open(os.path.join(CACHE_DIR_UNET, f"att_vulnerable_batch_{batch_index}.pkl"), 'wb') as f:
        pickle.dump((X_vulnerable_att, Y_vulnerable), f)
    with open(os.path.join(CACHE_DIR_UNET, f"att_sensitive_negative_batch_{batch_index}.pkl"), 'wb') as f:
        pickle.dump((X_sensitive_negative_att, Y_sensitive_negative), f)
    with open(os.path.join(CACHE_DIR_UNET, f"att_safe_batch_{batch_index}.pkl"), 'wb') as f:
        pickle.dump((X_safe_att, Y_safe), f)

    print(f"Batch {batch_index} saved in {CACHE_DIR_UNET}: embedding (emb_) + attention_map (att_) files")


def build_unet_branch(input_shape):
    inputs = Input(shape=input_shape, name='attention_map_input')

    conv1 = Conv2D(64, (3, 3), activation='relu', padding='same')(inputs)
    pool1 = MaxPooling2D((2, 2))(conv1)

    conv2 = Conv2D(128, (3, 3), activation='relu', padding='same')(pool1)
    pool2 = MaxPooling2D((2, 2))(conv2)

    conv3 = Conv2D(256, (3, 3), activation='relu', padding='same')(pool2)

    up1 = UpSampling2D((2, 2))(conv3)
    concat1 = concatenate([conv2, up1])
    conv4 = Conv2D(128, (3, 3), activation='relu', padding='same')(concat1)

    up2 = UpSampling2D((2, 2))(conv4)
    concat2 = concatenate([conv1, up2])
    conv5 = Conv2D(64, (3, 3), activation='relu', padding='same')(concat2)

    pooled = GlobalAveragePooling2D()(conv5)
    dense_out = Dense(128, activation='relu')(pooled)

    return inputs, dense_out


def build_bilstm_branch(input_shape):
    inputs = Input(shape=input_shape, name='embedding_input')
    x = Bidirectional(LSTM(128, return_sequences=True))(inputs)
    x = Dropout(0.5)(x)
    x = Bidirectional(LSTM(64))(x)
    return inputs, x


def build_unet_bilstm_model(seq_len=sequence_length, vec_len=vector_length):
    unet_input, unet_output = build_unet_branch((seq_len, seq_len, 1))
    lstm_input, lstm_output = build_bilstm_branch((seq_len, vec_len))

    combined = concatenate([unet_output, lstm_output])
    dense1 = Dense(128, activation='relu')(combined)
    dense2 = Dense(64, activation='relu')(dense1)
    outputs = Dense(1, activation='sigmoid')(dense2)

    model = Model(inputs=[unet_input, lstm_input], outputs=outputs)
    return model


def train_UNET_LSTM():
    X_att, Y_att = load_batches_by_prefix(CACHE_DIR_UNET, prefix="att_")
    X_emb, Y_emb = load_batches_by_prefix(CACHE_DIR_UNET, prefix="emb_")

    print(f"Shape of X_att (attention map): {X_att.shape}")
    print(f"Shape of X_emb (embedding): {X_emb.shape}")
    print(f"Shape of Y: {Y_att.shape}")

    assert np.array_equal(Y_att, Y_emb), "ترتیب Y بین att و emb یکسان نیست - فایل‌ها را بررسی کنید"

    print("Distribution in Y:", np.unique(Y_att, return_counts=True))

    indices = np.arange(len(Y_att))
    train_idx, test_idx = train_test_split(indices, test_size=0.2, random_state=42)

    X_att_train, X_att_test = X_att[train_idx], X_att[test_idx]
    X_emb_train, X_emb_test = X_emb[train_idx], X_emb[test_idx]
    Y_train, Y_test = Y_att[train_idx], Y_att[test_idx]

    print("Distribution in Y_test:", np.unique(Y_test, return_counts=True))

    model = build_unet_bilstm_model()

    model.compile(
        optimizer=Adam(learning_rate=0.001),
        loss=focal_loss(alpha=0.25, gamma=2.0),
        metrics=['accuracy']
    )

    model.summary()

    early_stopping = EarlyStopping(
        monitor='val_loss',
        patience=10,
        restore_best_weights=True
    )

    history = model.fit(
        [X_att_train, X_emb_train], Y_train,
        epochs=50,
        batch_size=128,
        validation_split=0.2,
        callbacks=[early_stopping],
        verbose=2
    )

    os.makedirs(os.path.join(ROOT, 'output'), exist_ok=True)
    plt.figure(figsize=(10, 6))
    plt.plot(history.history['accuracy'], label='train acc', color='blue')
    plt.plot(history.history['val_accuracy'], label='val acc', color='yellow')
    plt.plot(history.history['loss'], label='train loss', color='red')
    plt.plot(history.history['val_loss'], label='val loss', color='green')
    plt.title('U-Net(AttentionMap) + BiLSTM - Accuracy and Loss')
    plt.xlabel('Epochs')
    plt.ylabel('Accuracy / Loss')
    plt.legend(loc='best')
    plt.grid()

    os.makedirs(os.path.join(ROOT, 'output'), exist_ok=True)
    output_image_path = os.path.join(ROOT, 'output', 'training_plot_unet_attention_lstm.png')
    plt.savefig(output_image_path, dpi=300, bbox_inches='tight')
    print(f"Plot saved to {output_image_path}")
    plt.show()

    Y_pred = (model.predict([X_att_test, X_emb_test]) > 0.5).astype("int32")

    accuracy = accuracy_score(Y_test, Y_pred)
    report = classification_report(Y_test, Y_pred, target_names=['Safe', 'Vulnerable'], labels=[0, 1])

    print(f"Accuracy: {accuracy}")
    print("Classification Report:")
    print(report)

    model.save(os.path.join(ROOT, 'output', 'final_unet_attention_lstm_model.h5'))
    print("Training complete with U-Net(AttentionMap) + BiLSTM.")


def train_LSTM():
    X, Y = load_batches_by_prefix(CACHE_DIR_UNET, prefix="emb_")
    print(f"Shape of X: {X.shape}")
    print(f"Shape of Y: {Y.shape}")
    print("Distribution in Y:", np.unique(Y, return_counts=True))

    X_train, X_test, Y_train, Y_test = train_test_split(X, Y, test_size=0.2, random_state=42)
    print("Distribution in Y_test:", np.unique(Y_test, return_counts=True))

    model = Sequential([
        Input(shape=(X_train.shape[1], X_train.shape[2])),
        Bidirectional(LSTM(128, return_sequences=True)),
        Dropout(0.5),
        Bidirectional(LSTM(64)),
        Dense(1, activation='sigmoid')
    ])

    model.compile(
        optimizer=Adam(learning_rate=0.001),
        loss=focal_loss(alpha=0.25, gamma=2.0),
        metrics=['accuracy']
    )

    early_stopping = EarlyStopping(
        monitor='val_loss',
        patience=10,
        restore_best_weights=True
    )

    history = model.fit(
        X_train, Y_train,
        epochs=50,
        batch_size=128,
        validation_split=0.2,
        callbacks=[early_stopping],
        verbose=2
    )

    os.makedirs(os.path.join(ROOT, 'output'), exist_ok=True)

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

    output_image_path = os.path.join(ROOT, 'output', 'training_plot_lstm.png')
    plt.savefig(output_image_path, dpi=300, bbox_inches='tight')
    print(f"Plot saved to {output_image_path}")

    plt.show()

    Y_pred = (model.predict(X_test) > 0.5).astype("int32")

    accuracy = accuracy_score(Y_test, Y_pred)
    report = classification_report(Y_test, Y_pred, target_names=['Safe', 'Vulnerable'], labels=[0, 1])

    print(f"Accuracy: {accuracy}")
    print("Classification Report:")
    print(report)

    model.save(os.path.join(ROOT, 'output', 'final_LSTM_model.h5'))

    print("Training complete with LSTM.")


def build_unet_only_model(seq_len=sequence_length):
    unet_input, unet_output = build_unet_branch((seq_len, seq_len, 1))
    dense1 = Dense(64, activation='relu')(unet_output)
    outputs = Dense(1, activation='sigmoid')(dense1)
    model = Model(inputs=unet_input, outputs=outputs)
    return model


# =============================================================================
# اصلاح شد (نسخه نهایی): build_feature_extractor_lstm / build_feature_extractor_unet
# روش قبلی (chain کردن دستی لایه‌ها روی full_model.layers) برای LSTM کار
# می‌کرد اما برای U-Net با خطا مواجه شد، چون U-Net لایه‌های concatenate
# (skip-connection) دارد که به چند خروجی قبلی نیاز دارند - نه فقط خروجی
# بلافصل قبلی - و chain خطی این ساختار را می‌شکند.
#
# راه‌حل قطعی: معماری از صفر و با همان توابع build موجود (build_unet_branch،
# build_bilstm_branch) بازسازی می‌شود - دقیقاً همان گراف صحیح با
# skip-connection - و فقط وزن‌ها از مدل ذخیره‌شده کپی می‌شوند. این کاملاً
# مستقل از هر باگ ردیابی گراف در Keras است.
# =============================================================================
def build_feature_extractor_lstm(seq_len=sequence_length, vec_len=vector_length):
    inputs = Input(shape=(seq_len, vec_len))
    x = Bidirectional(LSTM(128, return_sequences=True))(inputs)
    x = Dropout(0.5)(x)
    x = Bidirectional(LSTM(64))(x)
    return KerasModel(inputs=inputs, outputs=x)


def build_feature_extractor_unet(seq_len=sequence_length):
    unet_input, unet_output = build_unet_branch((seq_len, seq_len, 1))
    dense1 = Dense(64, activation='relu')(unet_output)
    return KerasModel(inputs=unet_input, outputs=dense1)


# =============================================================================
# اصلاح شد (نسخه نهایی): extract_penultimate_features_and_prob
# پارامتر model_type ('lstm' یا 'unet') اضافه شد تا معماری صحیح از صفر
# ساخته شود. وزن‌ها با full_model.get_weights()[:-2] کپی می‌شوند - یعنی
# همه وزن‌ها به‌جز دو آرایه آخر (kernel و bias لایه Dense(1,sigmoid) نهایی)
# که این معماری feature-extractor آن‌ها را ندارد.
# =============================================================================
def extract_penultimate_features_and_prob(model_path, X_data, model_type):
    full_model = load_model(
        model_path,
        custom_objects={'loss': focal_loss(alpha=0.25, gamma=2.0)}
    )

    if model_type == 'lstm':
        feature_extractor = build_feature_extractor_lstm()
    elif model_type == 'unet':
        feature_extractor = build_feature_extractor_unet()
    else:
        raise ValueError("model_type باید 'lstm' یا 'unet' باشد")

    full_weights = full_model.get_weights()
    feature_extractor.set_weights(full_weights[:-2])  # بدون وزن‌های Dense(1,sigmoid) نهایی

    features = feature_extractor.predict(X_data, verbose=0)
    prob = full_model.predict(X_data, verbose=0).flatten()
    feat_dim = features.shape[-1]
    return features, prob, feat_dim


# =============================================================================
# build_feature_stacking_model
# مدل fusion که هم بردار ویژگی میانی (feature) و هم احتمال خام (probability)
# هر دو شاخه را می‌گیرد. BatchNormalization برای پایداری آموزش اضافه شده.
# =============================================================================
def build_feature_stacking_model(lstm_feat_dim, unet_feat_dim):
    lstm_feat_input = Input(shape=(lstm_feat_dim,), name='lstm_features')
    unet_feat_input = Input(shape=(unet_feat_dim,), name='unet_features')
    prob_input = Input(shape=(4,), name='prob_features')  # p_lstm, p_unet, |diff|, product

    lstm_norm = BatchNormalization()(lstm_feat_input)
    unet_norm = BatchNormalization()(unet_feat_input)

    combined = concatenate([lstm_norm, unet_norm, prob_input])
    x = Dense(64, activation='relu')(combined)
    x = Dropout(0.4)(x)
    x = Dense(32, activation='relu')(x)
    x = Dropout(0.3)(x)
    x = Dense(16, activation='relu')(x)
    output = Dense(1, activation='sigmoid')(x)

    model = Model(inputs=[lstm_feat_input, unet_feat_input, prob_input], outputs=output)
    return model


# =============================================================================
# train_feature_level_stacking
# مدل‌های LSTM و U-Net کاملاً منجمد هستند - فقط برای استخراج ویژگی
# استفاده می‌شوند. نیازمند وجود final_LSTM_model.h5 و
# final_unet_only_model.h5 در پوشه output است - نیازی به train مجدد آن‌ها نیست.
# =============================================================================
def train_feature_level_stacking():
    X_att, Y_att = load_batches_by_prefix(CACHE_DIR_UNET, prefix="att_")
    X_emb, Y_emb = load_batches_by_prefix(CACHE_DIR_UNET, prefix="emb_")
    assert np.array_equal(Y_att, Y_emb), "ترتیب Y بین att و emb یکسان نیست"

    indices = np.arange(len(Y_att))
    train_idx, test_idx = train_test_split(indices, test_size=0.2, random_state=42)

    X_att_train, X_att_test = X_att[train_idx], X_att[test_idx]
    X_emb_train, X_emb_test = X_emb[train_idx], X_emb[test_idx]
    Y_train, Y_test = Y_att[train_idx], Y_att[test_idx]

    lstm_path = os.path.join(ROOT, 'output', 'final_LSTM_model.h5')
    unet_path = os.path.join(ROOT, 'output', 'final_unet_only_model.h5')

    print("استخراج ویژگی و احتمال از LSTM (train)...")
    lstm_feat_train, p_lstm_train, lstm_dim = extract_penultimate_features_and_prob(lstm_path, X_emb_train, model_type='lstm')
    print("استخراج ویژگی و احتمال از LSTM (test)...")
    lstm_feat_test, p_lstm_test, _ = extract_penultimate_features_and_prob(lstm_path, X_emb_test, model_type='lstm')

    print("استخراج ویژگی و احتمال از U-Net (train)...")
    unet_feat_train, p_unet_train, unet_dim = extract_penultimate_features_and_prob(unet_path, X_att_train, model_type='unet')
    print("استخراج ویژگی و احتمال از U-Net (test)...")
    unet_feat_test, p_unet_test, _ = extract_penultimate_features_and_prob(unet_path, X_att_test, model_type='unet')

    print(f"LSTM feature dim: {lstm_dim}, U-Net feature dim: {unet_dim}")

    prob_train = np.column_stack([
        p_lstm_train, p_unet_train,
        np.abs(p_lstm_train - p_unet_train),
        p_lstm_train * p_unet_train
    ])
    prob_test = np.column_stack([
        p_lstm_test, p_unet_test,
        np.abs(p_lstm_test - p_unet_test),
        p_lstm_test * p_unet_test
    ])

    fusion_model = build_feature_stacking_model(lstm_dim, unet_dim)
    fusion_model.compile(
        optimizer=Adam(learning_rate=0.0005),
        loss=focal_loss(alpha=0.25, gamma=2.0),
        metrics=['accuracy']
    )
    fusion_model.summary()

    early_stopping = EarlyStopping(monitor='val_loss', patience=15, restore_best_weights=True)

    history = fusion_model.fit(
        [lstm_feat_train, unet_feat_train, prob_train], Y_train,
        epochs=100,
        batch_size=128,
        validation_split=0.2,
        callbacks=[early_stopping],
        verbose=2
    )

    os.makedirs(os.path.join(ROOT, 'output'), exist_ok=True)
    plt.figure(figsize=(10, 6))
    plt.plot(history.history['accuracy'], label='train acc', color='blue')
    plt.plot(history.history['val_accuracy'], label='val acc', color='yellow')
    plt.plot(history.history['loss'], label='train loss', color='red')
    plt.plot(history.history['val_loss'], label='val loss', color='green')
    plt.title('Feature-Level Stacking - Accuracy and Loss')
    plt.xlabel('Epochs')
    plt.ylabel('Accuracy / Loss')
    plt.legend(loc='best')
    plt.grid()
    output_image_path = os.path.join(ROOT, 'output', 'training_plot_feature_stacking.png')
    plt.savefig(output_image_path, dpi=300, bbox_inches='tight')
    print(f"Plot saved to {output_image_path}")
    plt.show()

    Y_pred = (fusion_model.predict([lstm_feat_test, unet_feat_test, prob_test]) > 0.5).astype("int32")
    accuracy = accuracy_score(Y_test, Y_pred)

    lstm_only_pred = (p_lstm_test > 0.5).astype("int32")
    lstm_only_accuracy = accuracy_score(Y_test, lstm_only_pred)

    print(f"\n{'='*50}")
    print(f"LSTM-only accuracy:              {lstm_only_accuracy:.4f}")
    print(f"Feature-Level Stacking Accuracy: {accuracy:.4f}")
    print(f"بهبود نسبت به LSTM تنها:          {(accuracy - lstm_only_accuracy) * 100:.2f} درصد")
    print(f"{'='*50}\n")
    print("Classification Report:")
    print(classification_report(Y_test, Y_pred, target_names=['Safe', 'Vulnerable'], labels=[0, 1]))

    fusion_model.save(os.path.join(ROOT, 'output', 'final_feature_stacking.h5'))
    print(f"Model saved to {os.path.join(ROOT, 'output', 'final_feature_stacking.h5')}")


if __name__ == "__main__":
    files = [os.path.join(PATH, f) for f in os.listdir(PATH) if f.endswith(".sol")]
    print(f"size files {files.__len__()}")

    # for batch_index, i in enumerate(range(0, len(files), batch_size)):
    #     batch_files = files[i:i + batch_size]
    #     print(f"size batch_files {batch_files.__len__()}")
    #     process_batch_with_categorization(batch_files, target_vulner, batch_size, batch_index)
    #     process_batch_with_categorization_for_unet(batch_files, target_vulner, batch_size, batch_index)

    # train_LSTM()
    # train_UNET_LSTM()
    # test_unet_branch_alone()
    # check_ensemble_potential()
    train_feature_level_stacking()


# 2026-07-07 11:02:21.031696: I tensorflow/core/util/port.cc:153] oneDNN custom operations are on. You may see slightly different numerical results due to floating-point round-off errors from different computation orders. To turn them off, set the environment variable `TF_ENABLE_ONEDNN_OPTS=0`.
# 2026-07-07 11:02:21.099100: I tensorflow/core/platform/cpu_feature_guard.cc:210] This TensorFlow binary is optimized to use available CPU instructions in performance-critical operations.
# To enable the following instructions: AVX2 AVX512F AVX512_VNNI FMA, in other operations, rebuild TensorFlow with the appropriate compiler flags.
# size files 47398
# استخراج ویژگی و احتمال از LSTM (train)...
# 2026-07-07 11:02:37.410004: W tensorflow/core/common_runtime/gpu/gpu_bfc_allocator.cc:47] Overriding orig_value setting because the TF_FORCE_GPU_ALLOW_GROWTH environment variable is set. Original config value was 0.
# WARNING: All log messages before absl::InitializeLog() is called are written to STDERR
# I0000 00:00:1783422157.410981    6897 gpu_device.cc:2020] Created device /job:localhost/replica:0/task:0/device:GPU:0 with 38477 MB memory:  -> device: 0, name: NVIDIA A100-SXM4-40GB, pci bus id: 0000:00:04.0, compute capability: 8.0
# WARNING:absl:Compiled the loaded model, but the compiled metrics have yet to be built. `model.compile_metrics` will be empty until you train or evaluate the model.
# 2026-07-07 11:02:46.502436: I external/local_xla/xla/stream_executor/cuda/cuda_dnn.cc:473] Loaded cuDNN version 91900
# استخراج ویژگی و احتمال از LSTM (test)...
# WARNING:absl:Compiled the loaded model, but the compiled metrics have yet to be built. `model.compile_metrics` will be empty until you train or evaluate the model.
# استخراج ویژگی و احتمال از U-Net (train)...
# WARNING:absl:Compiled the loaded model, but the compiled metrics have yet to be built. `model.compile_metrics` will be empty until you train or evaluate the model.
# 2026-07-07 11:03:20.307748: I external/local_xla/xla/service/service.cc:163] XLA service 0x7e4784016a60 initialized for platform CUDA (this does not guarantee that XLA will be used). Devices:
# 2026-07-07 11:03:20.307771: I external/local_xla/xla/service/service.cc:171]   StreamExecutor device (0): NVIDIA A100-SXM4-40GB, Compute Capability 8.0
# 2026-07-07 11:03:20.348289: I tensorflow/compiler/mlir/tensorflow/utils/dump_mlir_util.cc:269] disabling MLIR crash reproducer, set env var `MLIR_CRASH_REPRODUCER_DIRECTORY` to enable.
# 2026-07-07 11:03:20.441505: I external/local_xla/xla/service/gpu/autotuning/dot_search_space.cc:208] All configs were filtered out because none of them sufficiently match the hints. Maybe the hints set does not contain a good representative set of valid configs? Working around this by using the full hints set instead.
# 2026-07-07 11:03:21.506815: I external/local_xla/xla/stream_executor/cuda/subprocess_compilation.cc:346] ptxas warning : Registers are spilled to local memory in function 'gemm_fusion_dot_121', 8 bytes spill stores, 8 bytes spill loads
#
# 2026-07-07 11:03:21.514939: I external/local_xla/xla/stream_executor/cuda/subprocess_compilation.cc:346] ptxas warning : Registers are spilled to local memory in function 'gemm_fusion_dot_121', 108 bytes spill stores, 108 bytes spill loads
#
# 2026-07-07 11:03:21.542419: I external/local_xla/xla/stream_executor/cuda/subprocess_compilation.cc:346] ptxas warning : Registers are spilled to local memory in function 'gemm_fusion_dot_121', 4 bytes spill stores, 4 bytes spill loads
#
# 2026-07-07 11:03:21.671189: I external/local_xla/xla/stream_executor/cuda/subprocess_compilation.cc:346] ptxas warning : Registers are spilled to local memory in function 'gemm_fusion_dot_121', 20 bytes spill stores, 20 bytes spill loads
#
# I0000 00:00:1783422203.427046    7061 device_compiler.h:196] Compiled cluster using XLA!  This line is logged at most once for the lifetime of the process.
# استخراج ویژگی و احتمال از U-Net (test)...
# WARNING:absl:Compiled the loaded model, but the compiled metrics have yet to be built. `model.compile_metrics` will be empty until you train or evaluate the model.
# 2026-07-07 11:03:41.204851: I external/local_xla/xla/service/gpu/autotuning/dot_search_space.cc:208] All configs were filtered out because none of them sufficiently match the hints. Maybe the hints set does not contain a good representative set of valid configs? Working around this by using the full hints set instead.
# 2026-07-07 11:03:41.666777: I external/local_xla/xla/stream_executor/cuda/subprocess_compilation.cc:346] ptxas warning : Registers are spilled to local memory in function 'gemm_fusion_dot_121', 12 bytes spill stores, 12 bytes spill loads
#
# 2026-07-07 11:03:42.352227: I external/local_xla/xla/stream_executor/cuda/subprocess_compilation.cc:346] ptxas warning : Registers are spilled to local memory in function 'gemm_fusion_dot_121', 292 bytes spill stores, 292 bytes spill loads
#
# 2026-07-07 11:03:42.360239: I external/local_xla/xla/stream_executor/cuda/subprocess_compilation.cc:346] ptxas warning : Registers are spilled to local memory in function 'gemm_fusion_dot_121', 4 bytes spill stores, 4 bytes spill loads
#
# 2026-07-07 11:03:42.364845: I external/local_xla/xla/stream_executor/cuda/subprocess_compilation.cc:346] ptxas warning : Registers are spilled to local memory in function 'gemm_fusion_dot_121', 8 bytes spill stores, 8 bytes spill loads
#
# 2026-07-07 11:03:42.443461: I external/local_xla/xla/stream_executor/cuda/subprocess_compilation.cc:346] ptxas warning : Registers are spilled to local memory in function 'gemm_fusion_dot_121', 24 bytes spill stores, 24 bytes spill loads
#
# LSTM feature dim: 128, U-Net feature dim: 64
# Model: "functional_12"
# ┏━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━┓
# ┃ Layer (type)        ┃ Output Shape      ┃    Param # ┃ Connected to      ┃
# ┡━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━┩
# │ lstm_features       │ (None, 128)       │          0 │ -                 │
# │ (InputLayer)        │                   │            │                   │
# ├─────────────────────┼───────────────────┼────────────┼───────────────────┤
# │ unet_features       │ (None, 64)        │          0 │ -                 │
# │ (InputLayer)        │                   │            │                   │
# ├─────────────────────┼───────────────────┼────────────┼───────────────────┤
# │ batch_normalization │ (None, 128)       │        512 │ lstm_features[0]… │
# │ (BatchNormalizatio… │                   │            │                   │
# ├─────────────────────┼───────────────────┼────────────┼───────────────────┤
# │ batch_normalizatio… │ (None, 64)        │        256 │ unet_features[0]… │
# │ (BatchNormalizatio… │                   │            │                   │
# ├─────────────────────┼───────────────────┼────────────┼───────────────────┤
# │ prob_features       │ (None, 4)         │          0 │ -                 │
# │ (InputLayer)        │                   │            │                   │
# ├─────────────────────┼───────────────────┼────────────┼───────────────────┤
# │ concatenate_4       │ (None, 196)       │          0 │ batch_normalizat… │
# │ (Concatenate)       │                   │            │ batch_normalizat… │
# │                     │                   │            │ prob_features[0]… │
# ├─────────────────────┼───────────────────┼────────────┼───────────────────┤
# │ dense_4 (Dense)     │ (None, 64)        │     12,608 │ concatenate_4[0]… │
# ├─────────────────────┼───────────────────┼────────────┼───────────────────┤
# │ dropout_2 (Dropout) │ (None, 64)        │          0 │ dense_4[0][0]     │
# ├─────────────────────┼───────────────────┼────────────┼───────────────────┤
# │ dense_5 (Dense)     │ (None, 32)        │      2,080 │ dropout_2[0][0]   │
# ├─────────────────────┼───────────────────┼────────────┼───────────────────┤
# │ dropout_3 (Dropout) │ (None, 32)        │          0 │ dense_5[0][0]     │
# ├─────────────────────┼───────────────────┼────────────┼───────────────────┤
# │ dense_6 (Dense)     │ (None, 16)        │        528 │ dropout_3[0][0]   │
# ├─────────────────────┼───────────────────┼────────────┼───────────────────┤
# │ dense_7 (Dense)     │ (None, 1)         │         17 │ dense_6[0][0]     │
# └─────────────────────┴───────────────────┴────────────┴───────────────────┘
#  Total params: 16,001 (62.50 KB)
#  Trainable params: 15,617 (61.00 KB)
#  Non-trainable params: 384 (1.50 KB)
# Epoch 1/100
# 2026-07-07 11:03:49.452730: I external/local_xla/xla/service/gpu/autotuning/dot_search_space.cc:208] All configs were filtered out because none of them sufficiently match the hints. Maybe the hints set does not contain a good representative set of valid configs? Working around this by using the full hints set instead.
# 2026-07-07 11:03:49.452857: I external/local_xla/xla/service/gpu/autotuning/dot_search_space.cc:208] All configs were filtered out because none of them sufficiently match the hints. Maybe the hints set does not contain a good representative set of valid configs? Working around this by using the full hints set instead.
# 2026-07-07 11:03:49.452882: I external/local_xla/xla/service/gpu/autotuning/dot_search_space.cc:208] All configs were filtered out because none of them sufficiently match the hints. Maybe the hints set does not contain a good representative set of valid configs? Working around this by using the full hints set instead.
# 2026-07-07 11:03:49.452904: I external/local_xla/xla/service/gpu/autotuning/dot_search_space.cc:208] All configs were filtered out because none of them sufficiently match the hints. Maybe the hints set does not contain a good representative set of valid configs? Working around this by using the full hints set instead.
# 2026-07-07 11:03:49.452921: I external/local_xla/xla/service/gpu/autotuning/dot_search_space.cc:208] All configs were filtered out because none of them sufficiently match the hints. Maybe the hints set does not contain a good representative set of valid configs? Working around this by using the full hints set instead.
# 2026-07-07 11:03:50.951370: I external/local_xla/xla/stream_executor/cuda/subprocess_compilation.cc:346] ptxas warning : Registers are spilled to local memory in function 'gemm_fusion_dot_410', 212 bytes spill stores, 208 bytes spill loads
#
# 2026-07-07 11:03:51.359666: I external/local_xla/xla/stream_executor/cuda/subprocess_compilation.cc:346] ptxas warning : Registers are spilled to local memory in function 'gemm_fusion_dot_410', 340 bytes spill stores, 340 bytes spill loads
#
# 2026-07-07 11:03:51.983366: I external/local_xla/xla/stream_executor/cuda/subprocess_compilation.cc:346] ptxas warning : Registers are spilled to local memory in function 'gemm_fusion_dot_410', 644 bytes spill stores, 576 bytes spill loads
#
# 2026-07-07 11:03:52.542929: I external/local_xla/xla/stream_executor/cuda/subprocess_compilation.cc:346] ptxas warning : Registers are spilled to local memory in function 'gemm_fusion_dot_1505', 308 bytes spill stores, 308 bytes spill loads
#
# 2026-07-07 11:03:52.750852: I external/local_xla/xla/stream_executor/cuda/subprocess_compilation.cc:346] ptxas warning : Registers are spilled to local memory in function 'gemm_fusion_dot_1426', 116 bytes spill stores, 116 bytes spill loads
#
# 2026-07-07 11:03:53.224484: I external/local_xla/xla/stream_executor/cuda/subprocess_compilation.cc:346] ptxas warning : Registers are spilled to local memory in function 'gemm_fusion_dot_1489', 308 bytes spill stores, 308 bytes spill loads
#
# 2026-07-07 11:03:53.382346: I external/local_xla/xla/stream_executor/cuda/subprocess_compilation.cc:346] ptxas warning : Registers are spilled to local memory in function 'gemm_fusion_dot_1489', 8 bytes spill stores, 8 bytes spill loads
#
# 2026-07-07 11:03:53.660176: I external/local_xla/xla/stream_executor/cuda/subprocess_compilation.cc:346] ptxas warning : Registers are spilled to local memory in function 'gemm_fusion_dot_1505', 128 bytes spill stores, 128 bytes spill loads
#
# 2026-07-07 11:03:54.220963: I external/local_xla/xla/stream_executor/cuda/subprocess_compilation.cc:346] ptxas warning : Registers are spilled to local memory in function 'gemm_fusion_dot_1489', 72 bytes spill stores, 72 bytes spill loads
#
# 2026-07-07 11:03:54.233931: I external/local_xla/xla/stream_executor/cuda/subprocess_compilation.cc:346] ptxas warning : Registers are spilled to local memory in function 'gemm_fusion_dot_1489', 96 bytes spill stores, 96 bytes spill loads
#
# 2026-07-07 11:03:54.456704: I external/local_xla/xla/stream_executor/cuda/subprocess_compilation.cc:346] ptxas warning : Registers are spilled to local memory in function 'gemm_fusion_dot_1505', 76 bytes spill stores, 76 bytes spill loads
#
# 2026-07-07 11:03:58.353261: I external/local_xla/xla/stream_executor/cuda/subprocess_compilation.cc:346] ptxas warning : Registers are spilled to local memory in function 'gemm_fusion_dot_410', 8 bytes spill stores, 8 bytes spill loads
#
# 2026-07-07 11:04:01.841000: I external/local_xla/xla/service/gpu/autotuning/dot_search_space.cc:208] All configs were filtered out because none of them sufficiently match the hints. Maybe the hints set does not contain a good representative set of valid configs? Working around this by using the full hints set instead.
# 2026-07-07 11:04:03.118042: I external/local_xla/xla/stream_executor/cuda/subprocess_compilation.cc:346] ptxas warning : Registers are spilled to local memory in function 'gemm_fusion_dot_60', 244 bytes spill stores, 240 bytes spill loads
#
# 2026-07-07 11:04:03.367183: I external/local_xla/xla/stream_executor/cuda/subprocess_compilation.cc:346] ptxas warning : Registers are spilled to local memory in function 'gemm_fusion_dot_60', 16 bytes spill stores, 16 bytes spill loads
#
# 2026-07-07 11:04:03.528601: I external/local_xla/xla/stream_executor/cuda/subprocess_compilation.cc:346] ptxas warning : Registers are spilled to local memory in function 'gemm_fusion_dot_60', 648 bytes spill stores, 576 bytes spill loads
#
# 2026-07-07 11:04:03.610331: I external/local_xla/xla/stream_executor/cuda/subprocess_compilation.cc:346] ptxas warning : Registers are spilled to local memory in function 'gemm_fusion_dot_60', 340 bytes spill stores, 340 bytes spill loads
#
# 239/239 - 17s - 72ms/step - accuracy: 0.8649 - loss: 0.0210 - val_accuracy: 0.8492 - val_loss: 0.0224
# Epoch 2/100
# 239/239 - 1s - 3ms/step - accuracy: 0.9068 - loss: 0.0161 - val_accuracy: 0.8559 - val_loss: 0.0217
# Epoch 3/100
# 239/239 - 1s - 3ms/step - accuracy: 0.9122 - loss: 0.0154 - val_accuracy: 0.8540 - val_loss: 0.0220
# Epoch 4/100
# 239/239 - 1s - 3ms/step - accuracy: 0.9148 - loss: 0.0148 - val_accuracy: 0.8551 - val_loss: 0.0220
# Epoch 5/100
# 239/239 - 1s - 3ms/step - accuracy: 0.9166 - loss: 0.0143 - val_accuracy: 0.8538 - val_loss: 0.0224
# Epoch 6/100
# 239/239 - 1s - 3ms/step - accuracy: 0.9155 - loss: 0.0144 - val_accuracy: 0.8555 - val_loss: 0.0219
# Epoch 7/100
# 239/239 - 1s - 3ms/step - accuracy: 0.9182 - loss: 0.0140 - val_accuracy: 0.8569 - val_loss: 0.0216
# Epoch 8/100
# 239/239 - 1s - 3ms/step - accuracy: 0.9187 - loss: 0.0139 - val_accuracy: 0.8561 - val_loss: 0.0218
# Epoch 9/100
# 239/239 - 1s - 3ms/step - accuracy: 0.9174 - loss: 0.0138 - val_accuracy: 0.8564 - val_loss: 0.0217
# Epoch 10/100
# 239/239 - 1s - 3ms/step - accuracy: 0.9207 - loss: 0.0137 - val_accuracy: 0.8556 - val_loss: 0.0220
# Epoch 11/100
# 239/239 - 1s - 3ms/step - accuracy: 0.9210 - loss: 0.0134 - val_accuracy: 0.8558 - val_loss: 0.0219
# Epoch 12/100
# 239/239 - 1s - 3ms/step - accuracy: 0.9204 - loss: 0.0135 - val_accuracy: 0.8575 - val_loss: 0.0218
# Epoch 13/100
# 239/239 - 1s - 3ms/step - accuracy: 0.9200 - loss: 0.0136 - val_accuracy: 0.8585 - val_loss: 0.0217
# Epoch 14/100
# 239/239 - 1s - 3ms/step - accuracy: 0.9212 - loss: 0.0133 - val_accuracy: 0.8558 - val_loss: 0.0221
# Epoch 15/100
# 239/239 - 1s - 3ms/step - accuracy: 0.9211 - loss: 0.0134 - val_accuracy: 0.8572 - val_loss: 0.0217
# Epoch 16/100
# 239/239 - 1s - 3ms/step - accuracy: 0.9224 - loss: 0.0132 - val_accuracy: 0.8577 - val_loss: 0.0222
# Epoch 17/100
# 239/239 - 1s - 3ms/step - accuracy: 0.9211 - loss: 0.0133 - val_accuracy: 0.8571 - val_loss: 0.0220
# Epoch 18/100
# 239/239 - 1s - 3ms/step - accuracy: 0.9216 - loss: 0.0133 - val_accuracy: 0.8568 - val_loss: 0.0217
# Epoch 19/100
# 239/239 - 1s - 3ms/step - accuracy: 0.9221 - loss: 0.0132 - val_accuracy: 0.8565 - val_loss: 0.0216
# Epoch 20/100
# 239/239 - 1s - 3ms/step - accuracy: 0.9233 - loss: 0.0131 - val_accuracy: 0.8580 - val_loss: 0.0221
# Epoch 21/100
# 239/239 - 1s - 3ms/step - accuracy: 0.9225 - loss: 0.0131 - val_accuracy: 0.8568 - val_loss: 0.0219
# Epoch 22/100
# 239/239 - 1s - 3ms/step - accuracy: 0.9226 - loss: 0.0130 - val_accuracy: 0.8572 - val_loss: 0.0222
# Plot saved to /content/smartbugs-wild-with-content-and-result/output/training_plot_feature_stacking.png
# Figure(1000x600)
# 2026-07-07 11:04:19.215371: I external/local_xla/xla/service/gpu/autotuning/dot_search_space.cc:208] All configs were filtered out because none of them sufficiently match the hints. Maybe the hints set does not contain a good representative set of valid configs? Working around this by using the full hints set instead.
# 2026-07-07 11:04:20.388049: I external/local_xla/xla/stream_executor/cuda/subprocess_compilation.cc:346] ptxas warning : Registers are spilled to local memory in function 'gemm_fusion_dot_46', 204 bytes spill stores, 176 bytes spill loads
#
# 2026-07-07 11:04:20.579707: I external/local_xla/xla/stream_executor/cuda/subprocess_compilation.cc:346] ptxas warning : Registers are spilled to local memory in function 'gemm_fusion_dot_46', 216 bytes spill stores, 232 bytes spill loads
#
# 2026-07-07 11:04:20.646130: I external/local_xla/xla/stream_executor/cuda/subprocess_compilation.cc:346] ptxas warning : Registers are spilled to local memory in function 'gemm_fusion_dot_46', 92 bytes spill stores, 92 bytes spill loads
#
# 2026-07-07 11:04:20.706256: I external/local_xla/xla/stream_executor/cuda/subprocess_compilation.cc:346] ptxas warning : Registers are spilled to local memory in function 'gemm_fusion_dot_46', 740 bytes spill stores, 552 bytes spill loads
#
# 279/298 ━━━━━━━━━━━━━━━━━━━━ 0s 1ms/step2026-07-07 11:04:21.674762: I external/local_xla/xla/service/gpu/autotuning/dot_search_space.cc:208] All configs were filtered out because none of them sufficiently match the hints. Maybe the hints set does not contain a good representative set of valid configs? Working around this by using the full hints set instead.
# 2026-07-07 11:04:22.091207: I external/local_xla/xla/stream_executor/cuda/subprocess_compilation.cc:346] ptxas warning : Registers are spilled to local memory in function 'gemm_fusion_dot_46', 8 bytes spill stores, 8 bytes spill loads
#
# 2026-07-07 11:04:23.072049: I external/local_xla/xla/stream_executor/cuda/subprocess_compilation.cc:346] ptxas warning : Registers are spilled to local memory in function 'gemm_fusion_dot_46', 92 bytes spill stores, 92 bytes spill loads
#
# 2026-07-07 11:04:23.088414: I external/local_xla/xla/stream_executor/cuda/subprocess_compilation.cc:346] ptxas warning : Registers are spilled to local memory in function 'gemm_fusion_dot_46', 204 bytes spill stores, 176 bytes spill loads
#
# 2026-07-07 11:04:23.102412: I external/local_xla/xla/stream_executor/cuda/subprocess_compilation.cc:346] ptxas warning : Registers are spilled to local memory in function 'gemm_fusion_dot_46', 208 bytes spill stores, 224 bytes spill loads
#
# 2026-07-07 11:04:23.165962: I external/local_xla/xla/stream_executor/cuda/subprocess_compilation.cc:346] ptxas warning : Registers are spilled to local memory in function 'gemm_fusion_dot_46', 740 bytes spill stores, 552 bytes spill loads
#
# 298/298 ━━━━━━━━━━━━━━━━━━━━ 5s 9ms/step
#
# ==================================================
# LSTM-only accuracy:              0.8391
# Feature-Level Stacking Accuracy: 0.8544
# بهبود نسبت به LSTM تنها:          1.52 درصد
# ==================================================
#
# Classification Report:
#               precision    recall  f1-score   support
#
#         Safe       0.86      0.90      0.88      5683
#   Vulnerable       0.84      0.79      0.81      3841
#
#     accuracy                           0.85      9524
#    macro avg       0.85      0.84      0.85      9524
# weighted avg       0.85      0.85      0.85      9524
#
# WARNING:absl:You are saving your model as an HDF5 file via `model.save()` or `keras.saving.save_model(model)`. This file format is considered legacy. We recommend using instead the native Keras format, e.g. `model.save('my_model.keras')` or `keras.saving.save_model(model, 'my_model.keras')`.
# Model saved to /content/smartbugs-wild-with-content-and-result/output/final_feature_stacking.h5