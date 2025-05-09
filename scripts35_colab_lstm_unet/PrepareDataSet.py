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
from tensorflow.keras.layers import Conv2D, Conv1D, LeakyReLU, UpSampling1D, Concatenate, GlobalAveragePooling1D, Activation, Bidirectional, concatenate, Cropping2D, MaxPooling2D, MaxPooling1D, UpSampling2D, concatenate, Flatten, Dense, Bidirectional, LSTM, Input, Reshape, BatchNormalization, Reshape
from tensorflow.keras.models import Model
from tensorflow.keras import layers, models
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.callbacks import EarlyStopping
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


def train_LSTM():
    # بارگذاری داده‌ها
    X, Y = load_batches(CACHE_DIR, file_extension=".pkl")
    print(f"Shape of X: {X.shape}")
    print(f"Shape of Y: {Y.shape}")
    print("Distribution in Y:", np.unique(Y, return_counts=True))

    # تقسیم داده‌ها به آموزش و تست
    X_train, X_test, Y_train, Y_test = train_test_split(X, Y, test_size=0.2, random_state=42)
    print("Distribution in Y_test:", np.unique(Y_test, return_counts=True))

    # تعریف ورودی
    inputs = Input(shape=(X_train.shape[1], X_train.shape[2]))

    # شاخه U-Net
    conv1 = Conv1D(64, 3, activation='relu', padding='same')(inputs)
    pool1 = MaxPooling1D(2)(conv1)
    conv2 = Conv1D(128, 3, activation='relu', padding='same')(pool1)
    pool2 = MaxPooling1D(2)(conv2)
    conv3 = Conv1D(256, 3, activation='relu', padding='same')(pool2)
    unet_output = GlobalAveragePooling1D()(conv3)

    # شاخه LSTM (بدون تغییر)
    lstm1 = Bidirectional(LSTM(128, return_sequences=True))(inputs)
    lstm2 = Bidirectional(LSTM(64))(lstm1)

    # ترکیب خروجی‌ها
    combined = Concatenate()([unet_output, lstm2])

    # لایه خروجی
    output = Dense(1, activation='sigmoid')(combined)

    # ساخت مدل
    model = Model(inputs=inputs, outputs=output)

    # کامپایل مدل
    model.compile(
        optimizer=Adam(learning_rate=0.001),
        loss="binary_crossentropy",
        metrics=['accuracy']
    )

    early_stopping = EarlyStopping(
        monitor='val_loss',
        patience=10,
        restore_best_weights=True
    )

    # آموزش مدل
    history = model.fit(
        X_train, Y_train,
        epochs=50,
        batch_size=32,
        validation_split=0.2,
        callbacks=[early_stopping],
        verbose=2
    )

    # رسم نمودار
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
    output_image_path = "training_plot_lstm_unet.png"
    plt.savefig(output_image_path, dpi=300, bbox_inches='tight')
    print(f"Plot saved to {output_image_path}")
    plt.show()

    # پیش‌بینی و ارزیابی
    Y_pred = (model.predict(X_test) > 0.5).astype("int32")
    accuracy = accuracy_score(Y_test, Y_pred)
    report = classification_report(Y_test, Y_pred, target_names=['Safe', 'Vulnerable'], labels=[0, 1])
    print(f"Accuracy: {accuracy}")
    print("Classification Report:")
    print(report)

    # ذخیره مدل
    model.save('final_LSTM_UNet_model.h5')
    print("Training complete with LSTM and U-Net.")

if __name__ == "__main__":
    train_LSTM()


#Epoch 1/50
# I0000 00:00:1745746482.222081   20369 cuda_dnn.cc:529] Loaded cuDNN version 90300
# 1211/1211 - 27s - 23ms/step - accuracy: 0.7545 - loss: 0.5040 - val_accuracy: 0.7833 - val_loss: 0.4537
# Epoch 2/50
# 1211/1211 - 19s - 16ms/step - accuracy: 0.7934 - loss: 0.4264 - val_accuracy: 0.7968 - val_loss: 0.4258
# Epoch 3/50
# 1211/1211 - 19s - 16ms/step - accuracy: 0.8038 - loss: 0.4047 - val_accuracy: 0.8103 - val_loss: 0.4012
# Epoch 4/50
# 1211/1211 - 19s - 16ms/step - accuracy: 0.8130 - loss: 0.3885 - val_accuracy: 0.8148 - val_loss: 0.3864
# Epoch 5/50
# 1211/1211 - 19s - 16ms/step - accuracy: 0.8219 - loss: 0.3734 - val_accuracy: 0.8147 - val_loss: 0.3806
# Epoch 6/50
# 1211/1211 - 19s - 16ms/step - accuracy: 0.8274 - loss: 0.3639 - val_accuracy: 0.8181 - val_loss: 0.3802
# Epoch 7/50
# 1211/1211 - 19s - 16ms/step - accuracy: 0.8332 - loss: 0.3539 - val_accuracy: 0.8205 - val_loss: 0.3756
# Epoch 8/50
# 1211/1211 - 19s - 16ms/step - accuracy: 0.8402 - loss: 0.3454 - val_accuracy: 0.8246 - val_loss: 0.3679
# Epoch 9/50
# 1211/1211 - 19s - 16ms/step - accuracy: 0.8429 - loss: 0.3385 - val_accuracy: 0.8306 - val_loss: 0.3635
# Epoch 10/50
# 1211/1211 - 19s - 16ms/step - accuracy: 0.8467 - loss: 0.3314 - val_accuracy: 0.8206 - val_loss: 0.3887
# Epoch 11/50
# 1211/1211 - 19s - 16ms/step - accuracy: 0.8506 - loss: 0.3264 - val_accuracy: 0.8329 - val_loss: 0.3585
# Epoch 12/50
# 1211/1211 - 19s - 16ms/step - accuracy: 0.8550 - loss: 0.3192 - val_accuracy: 0.8354 - val_loss: 0.3641
# Epoch 13/50
# 1211/1211 - 19s - 16ms/step - accuracy: 0.8583 - loss: 0.3128 - val_accuracy: 0.8349 - val_loss: 0.3608
# Epoch 14/50
# 1211/1211 - 19s - 16ms/step - accuracy: 0.8604 - loss: 0.3087 - val_accuracy: 0.8385 - val_loss: 0.3556
# Epoch 15/50
# 1211/1211 - 19s - 16ms/step - accuracy: 0.8654 - loss: 0.3032 - val_accuracy: 0.8374 - val_loss: 0.3624
# Epoch 16/50
# 1211/1211 - 19s - 16ms/step - accuracy: 0.8666 - loss: 0.2989 - val_accuracy: 0.8441 - val_loss: 0.3521
# Epoch 17/50
# 1211/1211 - 19s - 16ms/step - accuracy: 0.8683 - loss: 0.2948 - val_accuracy: 0.8410 - val_loss: 0.3529
# Epoch 18/50
# 1211/1211 - 19s - 16ms/step - accuracy: 0.8706 - loss: 0.2915 - val_accuracy: 0.8417 - val_loss: 0.3492
# Epoch 19/50
# 1211/1211 - 19s - 16ms/step - accuracy: 0.8750 - loss: 0.2842 - val_accuracy: 0.8472 - val_loss: 0.3546
# Epoch 20/50
# 1211/1211 - 19s - 16ms/step - accuracy: 0.8751 - loss: 0.2832 - val_accuracy: 0.8452 - val_loss: 0.3500
# Epoch 21/50
# 1211/1211 - 19s - 16ms/step - accuracy: 0.8765 - loss: 0.2776 - val_accuracy: 0.8434 - val_loss: 0.3563
# Epoch 22/50
# 1211/1211 - 19s - 16ms/step - accuracy: 0.8790 - loss: 0.2751 - val_accuracy: 0.8496 - val_loss: 0.3425
# Epoch 23/50
# 1211/1211 - 19s - 16ms/step - accuracy: 0.8808 - loss: 0.2709 - val_accuracy: 0.8505 - val_loss: 0.3521
# Epoch 24/50
# 1211/1211 - 19s - 16ms/step - accuracy: 0.8837 - loss: 0.2673 - val_accuracy: 0.8505 - val_loss: 0.3523
# Epoch 25/50
# 1211/1211 - 19s - 16ms/step - accuracy: 0.8844 - loss: 0.2631 - val_accuracy: 0.8502 - val_loss: 0.3427
# Epoch 26/50
# 1211/1211 - 19s - 16ms/step - accuracy: 0.8866 - loss: 0.2608 - val_accuracy: 0.8492 - val_loss: 0.3516
# Epoch 27/50
# 1211/1211 - 19s - 16ms/step - accuracy: 0.8874 - loss: 0.2588 - val_accuracy: 0.8442 - val_loss: 0.3590
# Epoch 28/50
# 1211/1211 - 19s - 16ms/step - accuracy: 0.8902 - loss: 0.2536 - val_accuracy: 0.8524 - val_loss: 0.3460
# Epoch 29/50
# 1211/1211 - 19s - 16ms/step - accuracy: 0.8910 - loss: 0.2503 - val_accuracy: 0.8512 - val_loss: 0.3524
# Epoch 30/50
# 1211/1211 - 19s - 16ms/step - accuracy: 0.8923 - loss: 0.2497 - val_accuracy: 0.8520 - val_loss: 0.3546
# Epoch 31/50
# 1211/1211 - 19s - 16ms/step - accuracy: 0.8923 - loss: 0.2475 - val_accuracy: 0.8491 - val_loss: 0.3588
# Epoch 32/50
# 1211/1211 - 19s - 16ms/step - accuracy: 0.8929 - loss: 0.2485 - val_accuracy: 0.8520 - val_loss: 0.3478
# Plot saved to training_plot_lstm_unet.png
# Figure(1000x600)
# 379/379 ━━━━━━━━━━━━━━━━━━━━ 3s 6ms/step
# Accuracy: 0.8549719193921375
# Classification Report:
#               precision    recall  f1-score   support
#
#         Safe       0.87      0.93      0.90      8308
#   Vulnerable       0.81      0.70      0.75      3800
#
#     accuracy                           0.85     12108
#    macro avg       0.84      0.81      0.82     12108
# weighted avg       0.85      0.85      0.85     12108
