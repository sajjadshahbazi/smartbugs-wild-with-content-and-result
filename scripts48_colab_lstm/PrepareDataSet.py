import os
import re
import json
import pickle
import numpy as np
from pathlib import Path
import PreProcessTools
from tensorflow.keras.preprocessing.sequence import pad_sequences
from sklearn.model_selection import train_test_split
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import LSTM, Dense, Dropout, Input
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.callbacks import EarlyStopping
from sklearn.metrics import accuracy_score, classification_report
import matplotlib.pyplot as plt
from sklearn.metrics import accuracy_score, classification_report, precision_score, recall_score, f1_score, confusion_matrix

# ==================== تنظیمات اصلی ====================
ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), '..'))

# پوشه vectorcollections01 در مسیر اصلی پروژه
CACHE_DIR = os.path.join(ROOT, 'vectorcollections01')
os.makedirs(CACHE_DIR, exist_ok=True)

# مسیر قراردادها
PATH = os.path.join(ROOT, 'contracts')
if not os.path.exists(PATH):
    raise FileNotFoundError(f"پوشه قراردادها پیدا نشد: {PATH}\nلطفاً پوشه contracts رو در کنار این فایل قرار بده.")

print(f"پروژه در: {ROOT}")
print(f"کش در: {CACHE_DIR}")
print(f"قراردادها در: {PATH}")

# ==================== تنظیمات ====================
sequence_length = 70
vector_length = 300
batch_size = 1000
output_name = 'icse20'


# ==================== تشخیص Reentrancy قوی ====================
def getResultVulnarable(contract_name):
    res = False
    lines = set()
    tools = ['mythril', 'slither', 'securify', 'smartcheck']

    for tool in tools:
        result_path = os.path.join(ROOT, 'results', tool, output_name, contract_name, 'result.json')
        if not os.path.exists(result_path):
            continue
        try:
            with open(result_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except:
            continue
        if not data or data.get('analysis') is None:
            continue

        if tool == 'mythril':
            for issue in data['analysis'].get('issues', []):
                if 'reentrancy' in str(issue.get('title', '')).lower():
                    res = True
                    if issue.get('lineno'):
                        lines.add(issue['lineno'])
        elif tool == 'slither':
            for result in data.get('analysis', []):
                if 'reentrancy' in str(result.get('check', '')).lower():
                    res = True
                    for elem in result.get('elements', []):
                        lines.update(elem.get('source_mapping', {}).get('lines', []))
        elif tool == 'securify':
            for contract in data['analysis']:
                for vuln in data['analysis'][contract].get('results', {}):
                    if 'reentrancy' in vuln.lower():
                        res = True
                        lines.update([l + 1 for l in data['analysis'][contract]['results'][vuln].get('violations', [])])
        elif tool == 'smartcheck':
            for issue in data['analysis']:
                if 'reentrancy' in str(issue.get('name', '')).lower():
                    res = True
                    if issue.get('line'):
                        lines.add(issue['line'])
    return res, list(lines)


# ==================== استخراج فانکشن‌ها ====================
def extract_functions_with_bodies(contract_code):
    functions = []
    pattern = re.compile(
        r'function\s+\w+\s*\(.*?\)\s*(public|private|internal|external)?\s*(view|pure)?\s*(returns\s*\(.*?\))?\s*{')
    lines = contract_code.splitlines()
    open_brackets = 0
    in_function = False
    function_body = []
    start_line = 0

    for i, line in enumerate(lines):
        if not in_function:
            if pattern.search(line):
                in_function = True
                start_line = i + 1
                function_body = [line]
                open_brackets = line.count('{') - line.count('}')
        else:
            function_body.append(line)
            open_brackets += line.count('{') - line.count('}')
            if open_brackets == 0:
                functions.append({
                    'function_body': '\n'.join(function_body),
                    'start_line': start_line,
                    'end_line': i + 1,
                    'label': 0
                })
                in_function = False
    return functions


# ==================== توکن‌سازی و وکتوریزه ====================
def tokenize_solidity_code(code):
    pattern = r'\b(?:function|returns|uint256|internal|constant|assert|return|require|if|else|for|while)\b|[=<>!*&|()+\-;/\}]|\b[a-zA-Z_][a-zA-Z0-9_]*\b'
    return re.findall(pattern, code)


def vectorize_tokens(tokens):
    from gensim.models import Word2Vec
    if not tokens:
        return np.zeros((sequence_length, vector_length), dtype='float32')
    model = Word2Vec([tokens], vector_size=vector_length, window=5, min_count=1, workers=4)
    vecs = [model.wv[t] if t in model.wv else np.zeros(vector_length) for t in tokens]
    vecs += [np.zeros(vector_length)] * (sequence_length - len(vecs))
    return np.array(vecs[:sequence_length], dtype='float32')


def label_functions_by_vulnerable_lines(functions, vulnerable_lines):
    for func in functions:
        if vulnerable_lines and any(func['start_line'] <= line <= func['end_line'] for line in vulnerable_lines):
            func['label'] = 1


def contains_sensitive_operator(body):
    return any(op in body for op in ['call', 'delegatecall', 'send', 'transfer', 'selfdestruct'])


# ==================== پردازش دسته‌ای ====================
def process_batch(files, batch_index):
    X_vul, Y_vul = [], []
    X_sens, Y_sens = [], []
    X_safe, Y_safe = [], []

    print(f"پردازش دسته {batch_index + 1} — {len(files)} قرارداد")

    for file_path in files:
        if not file_path.endswith(".sol"):
            continue
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                code = f.read()
        except:
            continue

        contract_name = Path(file_path).stem
        functions = extract_functions_with_bodies(code)
        is_vuln, vuln_lines = getResultVulnarable(contract_name)
        label_functions_by_vulnerable_lines(functions, vuln_lines)

        for func in functions:
            fragments = PreProcessTools.get_fragments(func['function_body'])
            func_vectors = []
            for frag in fragments:
                if frag.strip():
                    tokens = tokenize_solidity_code(frag)
                    if tokens:
                        vecs = vectorize_tokens(tokens)
                        func_vectors.extend(vecs)
            if func_vectors:
                padded = pad_sequences([func_vectors], maxlen=sequence_length, padding='post', dtype='float32')[0]
                label = func['label']
                if label == 1:
                    X_vul.append(padded)
                    Y_vul.append(1)
                elif contains_sensitive_operator(func['function_body']):
                    X_sens.append(padded)
                    Y_sens.append(0)
                else:
                    X_safe.append(padded)
                    Y_safe.append(0)

    # ذخیره در vectorcollections01 (مسیر اصلی پروژه)
    for name, X_data, Y_data in [
        ("vulnerable", X_vul, Y_vul),
        ("sensitive_negative", X_sens, Y_sens),
        ("safe", X_safe, Y_safe)
    ]:
        if X_data:
            path = os.path.join(CACHE_DIR, f"{name}_batch_{batch_index}.pkl")
            with open(path, 'wb') as f:
                pickle.dump((np.array(X_data), np.array(Y_data)), f)
            print(f"ذخیره شد → {name}: {len(X_data)} نمونه → {path}")


def load_batches(folder, file_extension=".pkl"):
    X_batches, Y_batches = [], []
    for file in os.listdir(folder):
        if file.endswith(file_extension):
            with open(os.path.join(folder, file), 'rb') as f:
                X, Y = pickle.load(f)
                if X.shape[1] != sequence_length:
                    X = pad_sequences(X, maxlen=sequence_length, padding='post', dtype='float32')
                X_batches.append(X)
                Y_batches.append(Y)
    return np.vstack(X_batches), np.hstack(Y_batches)


def train_LSTM():
    X, Y = load_batches(CACHE_DIR, file_extension=".pkl")
    print(f"Shape of X: {X.shape}")
    print(f"Shape of Y: {Y.shape}")
    print("Distribution in Y:", np.unique(Y, return_counts=True))

    X_train, X_test, Y_train, Y_test = train_test_split(X, Y, test_size=0.2, random_state=42)

    model = Sequential([
        Input(shape=(sequence_length, vector_length)),
        LSTM(64),
        Dropout(0.5),
        Dense(1, activation='sigmoid')
    ])

    model.compile(optimizer=Adam(0.001), loss='binary_crossentropy', metrics=['accuracy'])

    early_stopping = EarlyStopping(monitor='val_loss', patience=10, restore_best_weights=True)

    print("آموزش LSTM ساده شروع شد...")
    history = model.fit(X_train, Y_train, epochs=100, batch_size=128, validation_split=0.2,
                        callbacks=[early_stopping], verbose=2)

    # ==================== رسم و ذخیره نمودار در مسیر اصلی پروژه ====================
    plot_path = os.path.join(ROOT, 'lstm_training_plot.png')  # ذخیره در root پروژه
    plt.figure(figsize=(12, 8))
    plt.plot(history.history['accuracy'], label='Train Accuracy', color='blue', linewidth=2.5)
    plt.plot(history.history['val_accuracy'], label='Validation Accuracy', color='orange', linewidth=2.5)
    plt.plot(history.history['loss'], label='Train Loss', color='red', linewidth=2.5)
    plt.plot(history.history['val_loss'], label='Validation Loss', color='green', linewidth=2.5)
    plt.title('LSTM Model - Training & Validation Metrics', fontsize=16, fontweight='bold')
    plt.xlabel('Epochs', fontsize=14)
    plt.ylabel('Value', fontsize=14)
    plt.legend(fontsize=12)
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(plot_path, dpi=300, bbox_inches='tight')
    plt.show()
    print(f"نمودار با موفقیت ذخیره شد در:\n   {plot_path}")

    # ==================== پیش‌بینی و محاسبه معیارها ====================
    Y_pred_proba = model.predict(X_test)
    Y_pred = (Y_pred_proba > 0.5).astype(int).flatten()

    accuracy = accuracy_score(Y_test, Y_pred)
    precision = precision_score(Y_test, Y_pred)
    recall = recall_score(Y_test, Y_pred)
    f1 = f1_score(Y_test, Y_pred)
    cm = confusion_matrix(Y_test, Y_pred)

    print("\n" + "="*70)
    print("                نتایج نهایی مدل LSTM ساده")
    print("="*70)
    print(f"Accuracy           : {accuracy:.4f}")
    print(f"Precision          : {precision:.4f}")
    print(f"Recall             : {recall:.4f}")
    print(f"F1-Score           : {f1:.4f}")
    print("="*70)
    print(classification_report(Y_test, Y_pred, target_names=['Safe', 'Vulnerable'], digits=4))
    print("="*70)
    print("Confusion Matrix:")
    print(cm)
    print("="*70)

    # ذخیره مدل
    model_path = os.path.join(ROOT, 'simple_lstm_model.h5')
    model.save(model_path)
    print(f"مدل ذخیره شد در:\n   {model_path}")

if __name__ == "__main__":
    train_LSTM()