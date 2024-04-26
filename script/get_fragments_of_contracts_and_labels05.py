import numpy as np
import pandas as pd
from keras.preprocessing.text import Tokenizer
from keras.preprocessing.sequence import pad_sequences
from sklearn.model_selection import train_test_split
from imblearn.over_sampling import SMOTE
from keras.models import Sequential
from keras.layers import Embedding, LSTM, Dense, Dropout, SpatialDropout1D
from keras.layers import Conv1D, MaxPooling1D, Activation, Flatten
from keras.optimizers import Adam
from keras.callbacks import EarlyStopping
from sklearn.metrics import confusion_matrix, precision_score, recall_score, f1_score, accuracy_score

# Load data
data = pd.read_csv("smart_contracts.csv")
X = data["opcode_sequence"].values
y = data["label"].values

# Encode sequences
tokenizer = Tokenizer()
tokenizer.fit_on_texts(X)
X = tokenizer.texts_to_sequences(X)
max_length = max([len(x) for x in X])
X = pad_sequences(X, maxlen=max_length, padding="post")

# Split data
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# SMOTE oversampling
smote = SMOTE()
X_train_resampled, y_train_resampled = smote.fit_resample(X_train, y_train)

# Define LSTM model
lstm_model = Sequential()
lstm_model.add(Embedding(input_dim=len(tokenizer.word_index) + 1, output_dim=140, input_length=max_length))
lstm_model.add(SpatialDropout1D(0.6))
lstm_model.add(LSTM(96, dropout=0.6, recurrent_dropout=0.6))
lstm_model.add(LSTM(48, dropout=0.6, recurrent_dropout=0.6))
lstm_model.add(LSTM(48, dropout=0.6, recurrent_dropout=0.6))
lstm_model.add(Dropout(0.6))
lstm_model.add(Dense(1, activation="sigmoid"))

lstm_model.compile(optimizer=Adam(), loss="binary_crossentropy", metrics=["accuracy"])
early_stop = EarlyStopping(monitor="val_loss", patience=5)
lstm_model.fit(X_train_resampled, y_train_resampled, validation_split=0.15, epochs=50, batch_size=128, callbacks=[early_stop])

# Evaluate LSTM
y_pred_lstm = lstm_model.predict(X_test)
y_pred_lstm = (y_pred_lstm > 0.5).astype(int)
lstm_conf_matrix = confusion_matrix(y_test, y_pred_lstm)
lstm_precision = precision_score(y_test, y_pred_lstm)
lstm_recall = recall_score(y_test, y_pred_lstm)
lstm_f1 = f1_score(y_test, y_pred_lstm)
lstm_accuracy = accuracy_score(y_test, y_pred_lstm)

print("LSTM Results:")
print(f"Confusion Matrix:\n{lstm_conf_matrix}")
print(f"Precision: {lstm_precision:.4f}")
print(f"Recall: {lstm_recall:.4f}") 
print(f"F1-Score: {lstm_f1:.4f}")
print(f"Accuracy: {lstm_accuracy:.4f}")

# Define TCN model 
tcn_model = Sequential()
tcn_model.add(Embedding(input_dim=len(tokenizer.word_index) + 1, output_dim=140, input_length=max_length))
tcn_model.add(SpatialDropout1D(0.6))
tcn_model.add(Conv1D(filters=128, kernel_size=3, padding="causal", dilation_rate=1, activation="relu"))
tcn_model.add(Conv1D(filters=64, kernel_size=3, padding="causal", dilation_rate=2, activation="relu"))
tcn_model.add(Conv1D(filters=32, kernel_size=3, padding="causal", dilation_rate=4, activation="relu"))
tcn_model.add(MaxPooling1D(pool_size=2, padding="same", data_format="channels_last"))
tcn_model.add(Flatten())
tcn_model.add(Dense(1, activation="sigmoid"))

tcn_model.compile(optimizer=Adam(), loss="binary_crossentropy", metrics=["accuracy"])
early_stop = EarlyStopping(monitor="val_loss", patience=5)
tcn_model.fit(X_train_resampled, y_train_resampled, validation_split=0.15, epochs=50, batch_size=128, callbacks=[early_stop])

# Evaluate TCN
y_pred_tcn = tcn_model.predict(X_test)
y_pred_tcn = (y_pred_tcn > 0.5).astype(int)
tcn_conf_matrix = confusion_matrix(y_test, y_pred_tcn)
tcn_precision = precision_score(y_test, y_pred_tcn)
tcn_recall = recall_score(y_test, y_pred_tcn)
tcn_f1 = f1_score(y_test, y_pred_tcn)
tcn_accuracy = accuracy_score(y_test, y_pred_tcn)

print("\nTCN Results:")
print(f"Confusion Matrix:\n{tcn_conf_matrix}")
print(f"Precision: {tcn_precision:.4f}")
print(f"Recall: {tcn_recall:.4f}")
print(f"F1-Score: {tcn_f1:.4f}")  
print(f"Accuracy: {tcn_accuracy:.4f}")