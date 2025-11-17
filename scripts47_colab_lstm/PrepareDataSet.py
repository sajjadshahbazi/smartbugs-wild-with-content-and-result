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

# ==================== تنظیمات اصلی ====================
ROOT = '/content/smartbugs-wild-with-content-and-result'  # دیتاست اصلی
PATH = os.path.join(ROOT, 'contracts')  # فایل‌های .sol
CACHE_DIR = '/content/vectorcollections01'  # کش سریع در فضای داخلی Colab
output_name = 'icse20'
sequence_length = 70
vector_length = 300
batch_size = 1000

# ساخت پوشه کش
os.makedirs(CACHE_DIR, exist_ok=True)

# چک کردن وجود دیتاست
if not os.path.exists(PATH):
    raise FileNotFoundError(f"""
    پوشه قراردادها پیدا نشد!
    مسیر مورد انتظار: {PATH}

    لطفاً این کار رو انجام بده:
    1. فایل دیتاست رو آپلود کن به /content/
    2. یا از درایو unzip کن:
       !unzip /content/drive/MyDrive/smartbugs-wild-with-content-and-result.zip -d /content/
    """)

print(f"دیتاست پیدا شد: {len([f for f in os.listdir(PATH) if f.endswith('.sol')])} قرارداد هوشمند")
print(f"کش ذخیره می‌شود در: {CACHE_DIR}")


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

        # Mythril
        if tool == 'mythril':
            for issue in data['analysis'].get('issues', []):
                title = str(issue.get('title', '')).lower()
                if 'reentrancy' in title or 'reentrant' in title:
                    res = True
                    if issue.get('lineno'):
                        lines.add(issue['lineno'])

        # Slither — مهم‌ترین
        elif tool == 'slither':
            for result in data.get('analysis', []):
                check = str(result.get('check', '')).lower()
                if 'reentrancy' in check:
                    res = True
                    for elem in result.get('elements', []):
                        mapping = elem.get('source_mapping', {})
                        if 'lines' in mapping:
                            lines.update(mapping['lines'])

        # Securify
        elif tool == 'securify':
            for contract in data['analysis']:
                results = data['analysis'][contract].get('results', {})
                for vuln in results:
                    if 'reentrancy' in vuln.lower():
                        res = True
                        lines.update([l + 1 for l in results[vuln].get('violations', [])])

        # Smartcheck
        elif tool == 'smartcheck':
            for issue in data['analysis']:
                name = str(issue.get('name', '')).lower()
                if 'reentrancy' in name:
                    res = True
                    if issue.get('line'):
                        lines.add(issue['line'])

    return res, list(lines)


# ==================== استخراج فانکشن + توکن‌سازی + وکتوریزه ====================
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


def tokenize_solidity_code(code):
    pattern = r'\b(?:function|returns|uint256|internal|constant|assert|return|require|if|else|for|while)\b|[=<>!*&|()+\-;/\}]|\b[a-zA-Z_][a-zA-Z0-9_]*\b'
    return re.findall(pattern, code)


def vectorize_tokens(tokens):
    from gensim.models import Word2Vec
    if not tokens:
        return np.zeros((sequence_length, vector_length), dtype='float32')
    model = Word2Vec([tokens], vector_size=vector_length, window=5, min_count=1, workers=4)
    vecs = [model.wv[t] if t in model.wv else np.zeros(vector_length) for t in tokens]
    if len(vecs) < sequence_length:
        vecs += [np.zeros(vector_length)] * (sequence_length - len(vecs))
    return np.array(vecs[:sequence_length], dtype='float32')


def label_functions_by_vulnerable_lines(functions, vulnerable_lines):
    for func in functions:
        if vulnerable_lines and any(func['start_line'] <= line <= func['end_line'] for line in vulnerable_lines):
            func['label'] = 1


def contains_sensitive_operator(body):
    sensitive_ops = ['call', 'delegatecall', 'send', 'transfer', 'selfdestruct']
    return any(op in body for op in sensitive_ops)


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
            with open(file_path, 'r', encoding='utf-8') as f:
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

    # ذخیره سه دسته
    for name, X_data, Y_data in [
        ("vulnerable", X_vul, Y_vul),
        ("sensitive_negative", X_sens, Y_sens),
        ("safe", X_safe, Y_safe)
    ]:
        if X_data:
            path = os.path.join(CACHE_DIR, f"{name}_batch_{batch_index}.pkl")
            with open(path, 'wb') as f:
                pickle.dump((np.array(X_data), np.array(Y_data)), f)
            print(f"ذخیره شد → {name}: {len(X_data)} نمونه")


# ==================== آموزش LSTM ساده ====================
def train_simple_lstm():
    print("بارگذاری داده‌های پیش‌پردازش شده...")
    X_list, Y_list = [], []
    for pkl_file in Path(CACHE_DIR).glob("*.pkl"):
        with open(pkl_file, 'rb') as f:
            X_batch, Y_batch = pickle.load(f)
            X_list.append(X_batch)
            Y_list.append(Y_batch)

    X = np.vstack(X_list)
    Y = np.hstack(Y_list)
    print(f"دیتاست نهایی → X.shape: {X.shape} | Vulnerable: {Y.sum()} ({Y.sum() / len(Y) * 100:.2f}%)")

    X_train, X_test, Y_train, Y_test = train_test_split(X, Y, test_size=0.2, random_state=42, stratify=Y)

    model = Sequential([
        Input(shape=(sequence_length, vector_length)),
        LSTM(64),
        Dropout(0.5),
        Dense(1, activation='sigmoid')
    ])

    model.compile(
        optimizer=Adam(learning_rate=0.001),
        loss='binary_crossentropy',
        metrics=['accuracy']
    )

    early_stopping = EarlyStopping(monitor='val_accuracy', patience=8, restore_best_weights=True, mode='max')

    print("شروع آموزش LSTM ساده (Baseline برای مقایسه با U-Net+LSTM)...")
    history = model.fit(
        X_train, Y_train,
        epochs=100,
        batch_size=128,
        validation_split=0.2,
        callbacks=[early_stopping],
        verbose=2
    )

    # ارزیابی
    Y_pred = (model.predict(X_test) > 0.5).astype(int)
    acc = accuracy_score(Y_test, Y_pred)
    print(f"\nSimple LSTM Accuracy: {acc:.4f}")
    print(classification_report(Y_test, Y_pred, target_names=['Safe', 'Vulnerable']))

    model.save('/content/simple_lstm_baseline_70.h5')
    print("مدل ذخیره شد: /content/simple_lstm_baseline_70.h5")
    print("آماده برای ترکیب با U-Net و بهبود 8–10 درصدی!")


# ==================== اجرا ====================
if __name__ == "__main__":
    if any(Path(CACHE_DIR).glob("*.pkl")):
        print("داده‌های پیش‌پردازش شده پیدا شد → مستقیم آموزش LSTM ساده")
        train_simple_lstm()
    else:
        print("شروع پیش‌پردازش با sequence_length = 70")
        all_files = [os.path.join(PATH, f) for f in os.listdir(PATH) if f.endswith(".sol")]
        print(f"تعداد کل قراردادها: {len(all_files)}")
        for i in range(0, len(all_files), batch_size):
            batch_files = all_files[i:i + batch_size]
            process_batch(batch_files, i // batch_size)
        print("پیش‌پردازش تمام شد! دوباره این سلول رو اجرا کن تا مدل آموزش ببیند.")