import json
import re
import os
from pathlib import Path

import seaborn as sns

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
from sklearn.metrics import classification_report, accuracy_score, roc_auc_score, confusion_matrix
from tensorflow.keras.models import Sequential
# from tensorflow.keras.layers import Conv1D, Bidirectional, LSTM, Dropout, Dense
from tensorflow.keras.layers import Embedding, Bidirectional, LSTM, Dropout, Dense
from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau
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
batch_size = 1000  # کاهش اندازه دسته به 500 قرارداد
output_name = 'icse20'
vector_length = 300
tool_stat = {}
tool_category_stat = {}
total_duration = 0
contract_vulnerabilities = {}
sequence_length = 70
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


def load_all_data():
    X_list, y_list = [], []
    print("Loading all batches...")
    for file in os.listdir(CACHE_DIR):
        if file.endswith(".pkl"):
            path = os.path.join(CACHE_DIR, file)
            print(f"  Loading {file} ...")
            with open(path, 'rb') as f:
                X_batch, y_batch = pickle.load(f)
                X_list.append(X_batch)
                y_list.append(y_batch)

    X = np.vstack(X_list)
    y = np.hstack(y_list)

    print(f"\nDataset loaded successfully!")
    print(f"Total samples: {len(y)}")
    print(f"Shape: {X.shape} → (samples, 50, 300)  |  sequence_length در دیتا = 70 → pad به 50 شده")
    print(f"Safe functions    : {np.sum(y == 0):,}")
    print(f"Vulnerable functions: {np.sum(y == 1):,}")
    print(f"Class ratio: {np.sum(y == 1) / len(y) * 100:.2f}% vulnerable")
    return X, y


# ساخت مدل بهینه‌شده
def create_final_bilstm_model():
    model = Sequential([
        Input(shape=(50, 300)),  # دیتا با maxlen=50 ذخیره شده، ولی محتوا 70 توکن داره

        Bidirectional(LSTM(128, return_sequences=True, dropout=0.3, recurrent_dropout=0.2)),
        Dropout(0.5),

        Bidirectional(LSTM(64, dropout=0.3, recurrent_dropout=0.2)),
        Dropout(0.5),

        Dense(128, activation='relu'),
        Dropout(0.4),

        Dense(64, activation='relu'),
        Dropout(0.3),

        Dense(1, activation='sigmoid')
    ])

    model.compile(
        optimizer=Adam(learning_rate=0.001),
        loss='binary_crossentropy',
        metrics=['accuracy', 'Precision', 'Recall']
    )

    model.summary()
    return model


# اجرا
if __name__ == "__main__":
    X, y = load_all_data()

    # تقسیم با stratify برای حفظ تعادل کلاس
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print(f"\nTrain: {len(y_train):,} | Test: {len(y_test):,}")

    model = create_final_bilstm_model()

    callbacks = [
        EarlyStopping(monitor='val_accuracy', patience=12, restore_best_weights=True, verbose=1),
        ReduceLROnPlateau(monitor='val_loss', factor=0.5, patience=6, min_lr=1e-7, verbose=1)
    ]

    print("\nStarting training...")
    history = model.fit(
        X_train, y_train,
        validation_data=(X_test, y_test),
        epochs=100,
        batch_size=64,
        callbacks=callbacks,
        verbose=1
    )

    # رسم نمودار
    plt.figure(figsize=(15, 5))

    plt.subplot(1, 3, 1)
    plt.plot(history.history['accuracy'], label='Train Acc')
    plt.plot(history.history['val_accuracy'], label='Val Acc')
    plt.title('Accuracy')
    plt.legend();
    plt.grid(True)

    plt.subplot(1, 3, 2)
    plt.plot(history.history['loss'], label='Train Loss')
    plt.plot(history.history['val_loss'], label='Val Loss')
    plt.title('Loss')
    plt.legend();
    plt.grid(True)

    plt.subplot(1, 3, 3)
    plt.plot(history.history['Precision'], label='Precision')
    plt.plot(history.history['Recall'], label='Recall')
    plt.title('Precision & Recall')
    plt.legend();
    plt.grid(True)

    plt.tight_layout()
    plt.savefig("BiLSTM_sequence70_training_history.png", dpi=300, bbox_inches='tight')
    plt.show()

    # ارزیابی نهایی
    y_pred_prob = model.predict(X_test)
    y_pred = (y_pred_prob > 0.5).astype(int).flatten()

    acc = accuracy_score(y_test, y_pred)
    auc = roc_auc_score(y_test, y_pred_prob)

    print(f"\nFINAL RESULTS (sequence_length=70 + BiLSTM + Dropout):")
    print(f"Accuracy       : {acc:.4f}")
    print(f"AUC            : {auc:.4f}")
    print(f"F1-Score       : {classification_report(y_test, y_pred, digits=4).split()[-2]}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Safe', 'Vulnerable'], digits=4))

    # Confusion Matrix
    cm = confusion_matrix(y_test, y_pred)
    plt.figure(figsize=(6, 5))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=['Safe', 'Vulnerable'],
                yticklabels=['Safe', 'Vulnerable'])
    plt.title('Confusion Matrix')
    plt.ylabel('True')
    plt.xlabel('Predicted')
    plt.savefig("confusion_matrix.png", dpi=300, bbox_inches='tight')
    plt.show()

    # ذخیره مدل
    model.save("BiLSTM_Reentrancy_sequence70_Final.h5")
    print("\nModel saved: BiLSTM_Reentrancy_sequence70_Final.h5")
    print("Plot saved: BiLSTM_sequence70_training_history.png")
    print("این Baseline آماده است که با U-Net ترکیب بشه و بره بالای 94%!")