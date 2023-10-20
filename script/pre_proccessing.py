import re
import nltk
nltk.download('punkt')
from nltk.tokenize import word_tokenize



# Sample smart contract
# contract = """
# pragma solidity ^0.4.4;

#  Sample Smart Contract
# contract ProofExistence {
#     string public document;

#     constructor() public {
#         document = "Hello, World!";
#     }

#     function setDocument(string newDocument) public {
#         document = newDocument;
#     }
# }
# """

def remove_version(contract_text):
    # Remove solidity version pragma
    return re.sub(r'pragma solidity\s+\^?\d+\.\d+\.\d+;', '', contract_text)
    # return re.sub(r'pragma\s+solidity\s+\^[\d\.]+\s*;', '', contract_text)


def remove_comments_and_non_ascii(contract_text):
    # text = os.linesep.join([s for s in contract_text.splitlines() if s])

    # solidity_code = '\n'.join([line for line in contract_text.split('\n') if line.strip()])
    # solidity_code = '\n'.join(line for line in contract_text.split('\n') if line.strip())

    # # 3. Remove blank lines
    # contract_text = '\n'.join(line for line in contract_text.split('\n') if line.strip())
    #
    # # 4. Remove lines that have spaces
    # contract_text = '\n'.join(line for line in contract_text.split('\n') if not line.isspace() and not line.isspace())

    # 3. Remove blank lines
    solidity_codee = '\n'.join(line for line in contract_text.split('\n') if line.strip())

    # 4. Remove lines that just consist of spaces
    solidity_codeee = '\n'.join(line for line in solidity_codee.split('\n') if not line.isspace())

    # Remove comments (// and /* ... */)
    contract_text = re.sub(r'//.*?\n|/\*.*?\*/', '', solidity_codeee, flags=re.S)

    # Remove non-ASCII characters
    contract_text = ''.join(char for char in contract_text if ord(char) < 128)

    return contract_text

def rename_user_defined_identifiers(contract_text):
    # Replace user-defined function names and variable names with FUNX and VARX
    function_pattern = r'function\s+(\w+)\s*\('
    variable_pattern = r'(?:public|private|internal|external)?\s+(?:\w+\s+)*(\w+)\s*;'

    function_counter = 1
    variable_counter = 1

    def replace_function(match):
        nonlocal function_counter
        return f'function FUN{function_counter}('

    def replace_variable(match):
        nonlocal variable_counter
        return f'{match.group(1)} VAR{variable_counter};'

    contract_text = re.sub(function_pattern, replace_function, contract_text)
    contract_text = re.sub(variable_pattern, replace_variable, contract_text)

    return contract_text

def remove_whitespace_and_embed(contract_text):
    # Remove all spaces
    contract_text = ''.join(contract_text.split())

    # Perform word embedding (using gensim Word2Vec as an example)
    words = contract_text.split()

    return words


def run_tasks(contract):
    # Task 1: Remove solidity version pragma
    contract = remove_version(contract)

    # Task 2: Remove comments and non-ASCII characters
    contract = remove_comments_and_non_ascii(contract)

    # Task 3: Rename user-defined function and variable names
    contract = rename_user_defined_identifiers(contract)

    # Task 4: Remove whitespace and perform word embedding
    # words = remove_whitespace_and_embed(contract)

    # contract_model = fasttext.train_unsupervised(temp_file.name, model='skipgram', dim=100, minCount=1, thread=2)
    return contract


def run_takes01(solidity_code):
    # 1. Remove Solidity version pragma
    solidity_code = re.sub(r'pragma solidity\s+\^?\d+\.\d+\.\d+;', '', solidity_code)

    # 2. Remove comments and non-ASCII values
    solidity_code = re.sub(r'\/\/[^\n]*|\/\*[\s\S]*?\*\/|[^ -~]', ' ', solidity_code)

    # 3. Remove blank lines
    solidity_code = '\n'.join(line for line in solidity_code.split('\n') if line.strip())

    # 4. Remove lines that just consist of spaces
    solidity_code = '\n'.join(line for line in solidity_code.split('\n') if not line.isspace())

    # 5. Remove the first spaces before sentences on each line
    solidity_code = re.sub(r'^\s+', '', solidity_code, flags=re.MULTILINE)

    # 6. Represent user-defined function names as FUN plus numbers
    function_names = re.findall(r'function\s+(\w+)\s*\(', solidity_code)
    function_name_mapping = {}
    for i, name in enumerate(function_names):
        function_name_mapping[name] = f'FUN{i}'
    for name, replacement in function_name_mapping.items():
        solidity_code = re.sub(f'function\\s+{name}\\b', f'function {replacement}', solidity_code)

    # 7. Represent user-defined variable names as VAR plus numbers
    variable_names = re.findall(r'\bvar\s+(\w+)\s*;', solidity_code)
    variable_name_mapping = {}
    for i, name in enumerate(variable_names):
        variable_name_mapping[name] = f'VAR{i}'
    for name, replacement in variable_name_mapping.items():
        solidity_code = re.sub(f'\\bvar\\s+{name}\\s*;', f'var {replacement};', solidity_code)

    # Print the processed Solidity code
    print(solidity_code)

    # Extract words from the processed Solidity code
    words = re.findall(r'\b\w+\b', solidity_code)


def run_task02(solidity_codes):
    solidity_codes = re.sub(r'^\s*pragma\s+solidity\s+.*\n', '\n', solidity_codes, flags=re.MULTILINE)
    solidity_codes = re.sub(r'\/\/[^\n]*|\/\*[\s\S]*?\*\/|[^ -~]', ' ', solidity_codes)
    solidity_codes = '\n'.join(line for line in solidity_codes.split('\n') if line.strip())

    # 2. Tokenization
    tokens = word_tokenize(solidity_codes)
    return tokens
