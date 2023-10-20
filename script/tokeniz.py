import re
import gensim
import numpy as np

# Sample Solidity contract
# solidity_code = """
# pragma solidity ^0.4.4;
#
# contract ProofExistence {
#     string public document;
#
#     function setDocument(string newDocument) public {
#         document = newDocument;
#     }
# }
# """


def get_vec(solidity_code):
    # Remove Solidity version pragma
    # solidity_code = re.sub(r'pragma solidity\s+\^?\d+\.\d+\.\d+;', '', solidity_code)

    # Remove comments, non-ASCII characters, and blank lines
    # solidity_code = re.sub(r'\/\*.*?\*\/|\/\/.*?\n|[^ -~\t\n\r\f\v]+|\n\s*\n', '\n', solidity_code)

    # Replace user-defined function and variable names with placeholders
    # solidity_code = re.sub(r'function\s+\w+\s*\(', 'function FUN(', solidity_code)
    # solidity_code = re.sub(r'\bvar\s+\w+\s*;', 'var VAR;', solidity_code)

    # Remove spaces from the contract
    # solidity_code = ''.join(solidity_code.split())

    # Tokenize the contract into lines
    # contract_lines = solidity_code.split('\n')

    # Tokenize each line into characters
    # tokenized_lines = [list(line) for line in contract_lines]

    # Convert characters to word embeddings using Word2Vec (example)
    # model = gensim.models.Word2Vec(tokenized_lines, vector_size=100, window=5, min_count=1, sg=0)

    # Generate a matrix from the word embeddings
    # contract_matrix = np.array([model.wv[c] for line in tokenized_lines for c in line])

    # Print the word embeddings or use them for deep learning

    solidity_code = re.sub(r'pragma solidity\s+\^?\d+\.\d+\.\d+;', '', solidity_code)

    # Remove comments, non-ASCII characters, and blank lines
    solidity_code = re.sub(r'\/\/[^\n]*|\/\*[\s\S]*?\*\/|[^ -~\t\n\r\f\v]+|\n\s*\n', '\n', solidity_code)

    # Replace user-defined function names and variable names with placeholders
    solidity_code = re.sub(r'function\s+(\w+)\s*\(', r'function FUN\1(', solidity_code)
    solidity_code = re.sub(r'\bvar\s+(\w+)\s*;', r'var VAR\1;', solidity_code)

    # Remove all spaces from the contract
    solidity_code = ''.join(solidity_code.split())

    # Tokenize the contract into lines
    lines = solidity_code.split('\n')

    # Perform word embedding on each line and collect the word embeddings
    # word_embeddings = []
    # for line in lines:
    #     tokenized_line = list(line)
    #     model = gensim.models.Word2Vec([tokenized_line], vector_size=100, window=5, min_count=1, sg=0)
    #     line_embeddings = [model.wv[c] for c in tokenized_line]
    #     word_embeddings.extend(line_embeddings)

    # Convert the word embeddings to a NumPy array
    # contract_matrix = np.array(word_embeddings)

    # Print the word embeddings
    # for fragment in contract_matrix:
    #     print(' '.join(fragment))
    return lines
