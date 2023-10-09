import re


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
    # Remove comments (// and /* ... */)
    contract_text = re.sub(r'//.*?\n|/\*.*?\*/', '', contract_text, flags=re.S)
    
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

def runTasks(contract):
    # Task 1: Remove solidity version pragma
    contract = remove_version(contract)

    # Task 2: Remove comments and non-ASCII characters
    contract = remove_comments_and_non_ascii(contract)

    # Task 3: Rename user-defined function and variable names
    contract = rename_user_defined_identifiers(contract)

    # Task 4: Remove whitespace and perform word embedding
    words = remove_whitespace_and_embed(contract)

    # contract_model = fasttext.train_unsupervised(temp_file.name, model='skipgram', dim=100, minCount=1, thread=2)
    return words
    