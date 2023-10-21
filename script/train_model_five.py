import re
import os
import json

import numpy as np
from sklearn.model_selection import train_test_split
from keras.preprocessing.text import Tokenizer
from keras.preprocessing.sequence import pad_sequences
from keras.models import Sequential
from keras.layers import Embedding, LSTM, Dense
from sklearn.metrics import precision_score, recall_score, f1_score

# Sample Solidity contracts and labels (replace with your data)
ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), '..'))
path = f"{ROOT}\\contract\\" # temp data set
# path = f"{ROOT}\\contracts\\" # main data set

labels = []
contracts = []
output_name = 'icse20'
duration_stat = {}
tools = ['mythril','securify','maian','manticore', 'honeybadger']
count = {}
output = {}


def run_process(contracts, labels):
    # Example label(0 for safe, 1 for vulnerable)
    # contractsss = [preprocess_contract(contract) for contract in contractss]

    # print(contractsss)
    # print(labelss)

    # 2. Tokenization and Vectorization
    max_words = 10000  # Define the maximum number of words in your vocabulary
    # tokenizer = Tokenizer(num_words=max_words, char_level=True)
    # tokenizer.fit_on_texts(contractsss)
    # sequences = tokenizer.texts_to_sequences(contractsss)

    # 3. Sequence Padding
    max_sequence_length = 1000  # Choose an appropriate sequence length
    data = pad_sequences(contracts, maxlen=max_sequence_length)

    # 4. Split the data into training and testing sets
    X_train, X_test, y_train, y_test = train_test_split(data, labels, test_size=0.2, random_state=42)

    # 5. LSTM Model
    model = Sequential()
    model.add(Embedding(input_dim=max_words, output_dim=100, input_length=max_sequence_length))
    model.add(LSTM(100))
    model.add(Dense(1, activation='sigmoid'))

    model.compile(loss='binary_crossentropy', optimizer='adam', metrics=['accuracy'])

    X_train = np.array(X_train)
    X_test = np.array(X_test)
    y_test = np.array(y_test)
    y_train = np.array(y_train)

    # 6. Model Training
    model.fit(X_train, y_train, epochs=10, batch_size=64, validation_data=(X_test, y_test))

    # 7. Model Evaluation
    loss, accuracy = model.evaluate(X_test, y_test)

    y_pred = model.predict(X_test)

    print(f'Test loss: {loss}')
    print(f'Test accuracy: {accuracy}')

    precision = precision_score(y_test, (y_pred > 0.5).astype(int))
    recall = recall_score(y_test, (y_pred > 0.5).astype(int))
    f1 = f1_score(y_test, (y_pred > 0.5).astype(int))

    print(f'Precision: {precision}')
    print(f'Recall: {recall}')
    print(f'F1-Score: {f1}')


def preprocess_contract(contract):
    # Remove the solidity version pragma
    contract = re.sub(r'pragma\s+solidity\s+\^?\d+\.\d+\.\d+;', '', contract)
    # Remove every line containing 'pragma solidity'
    contract = re.sub(r'^\s*pragma\s+solidity\s+.*\n', '\n', contract, flags=re.MULTILINE)
    # Remove blank lines and lines with only spaces
    contract = re.sub(r'(?:(?:\r\n|\r|\n)\s*){2,}', '\n', contract)
    # Remove comments and non-ASCII characters
    contract = re.sub(r'\/\/[^\n]*|\/\*[\s\S]*?\*\/|[^ -~]', ' ', contract)
    return contract


def read_text_file(file_path, name):
    with open(file_path, encoding="utf8") as f:
        smartContractContent = f.read()
        # isVulnarable = ger_result_vulnarable(name)
        contracts.append(smartContractContent)
        isVal = 0
        # if (isVulnarable):
        #     isVal = 1

        labels.append(isVal)


os.chdir(path)


if __name__ == '__main__':
    print("DOROSTTTTTTTTTTTTTTT")
    for sss in ["1"]:
        for file in os.listdir():
            # Check whether file is in text format or not
            if file.endswith(".sol"):
                file_path = f"{path}\{file}"
                name = file.replace(".sol","")
                read_text_file(file_path, name)
run_process(contracts, labels)
