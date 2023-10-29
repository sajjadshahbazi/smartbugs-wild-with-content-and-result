import re
import warnings
import numpy as np
from gensim.models import Word2Vec



warnings.filterwarnings("ignore")

# Sets for operators
operators3 = {'<<=', '>>='}
operators2 = {
    '->', '++', '--',
    '!~', '<<', '>>', '<=', '>=',
    '==', '!=', '&&', '||', '+=',
    '-=', '*=', '/=', '%=', '&=', '^=', '|='
}
operators1 = {
    '(', ')', '[', ']', '.',
    '+', '-', '*', '&', '/',
    '%', '<', '>', '^', '|',
    '=', ',', '?', ':', ';',
    '{', '}'
}

"""
Functionality to train Word2Vec model and vectorize fragments
Trains Word2Vec model using list of tokenized fragments
Uses trained model embeddings to create 2D fragment vectors
"""

"""
Takes a line of solidity code (string) as input
Tokenizes solidity code (breaks down into identifier, variables, keywords, operators)
Returns a list of tokens, preserving order in which they appear
"""


@staticmethod
def tokenize(line):
    tmp, w = [], []
    i = 0
    while i < len(line):
        # Ignore spaces and combine previously collected chars to form words
        if line[i] == ' ':
            tmp.append(''.join(w))
            tmp.append(line[i])
            w = []
            i += 1
        # Check operators and append to final list
        elif line[i:i + 3] in operators3:
            tmp.append(''.join(w))
            tmp.append(line[i:i + 3])
            w = []
            i += 3
        elif line[i:i + 2] in operators2:
            tmp.append(''.join(w))
            tmp.append(line[i:i + 2])
            w = []
            i += 2
        elif line[i] in operators1:
            tmp.append(''.join(w))
            tmp.append(line[i])
            w = []
            i += 1
        # Character appended to word list
        else:
            w.append(line[i])
            i += 1
    # Filter out irrelevant strings
    res = list(filter(lambda c: c != '', tmp))
    return list(filter(lambda c: c != ' ', res))


"""
Tokenize entire fragment
Tokenize each line and concatenate to one long list
"""


@staticmethod
def tokenize_fragment(fragment):
    tokenized = []
    function_regex = re.compile('function(\d)+')
    backwards_slice = False
    for line in fragment:
        tokens = tokenize(line)
        tokenized += tokens
        if len(list(filter(function_regex.match, tokens))) > 0:
            backwards_slice = True
        else:
            backwards_slice = False
    return tokenized, backwards_slice


"""
Add input fragment to model
Tokenize fragment and buffer it to list
"""


def add_fragment(self, fragment):
    tokenized_fragment, backwards_slice = tokenize_fragment(fragment)
    self.fragments.append(tokenized_fragment)
    if backwards_slice:
        self.backward_slices += 1
    else:
        self.forward_slices += 1


"""
Uses Word2Vec to create a vector for each fragment
Gets a vector for the fragment by combining token embeddings
Number of tokens used is min of number_of_tokens and 100
"""


def vectorize(self, fragment):
    tokenized_fragment, backwards_slice = tokenize_fragment(fragment)
    vectors = np.zeros(shape=(100, self.vector_length))
    if backwards_slice:
        for i in range(min(len(tokenized_fragment), 100)):
            vectors[100 - 1 - i] = self.embeddings[tokenized_fragment[len(tokenized_fragment) - 1 - i]]
    else:
        for i in range(min(len(tokenized_fragment), 100)):
            vectors[i] = self.embeddings[tokenized_fragment[i]]
    return vectors

keywords = frozenset(
    {'bool', 'break', 'case', 'catch', 'const', 'continue', 'default', 'do', 'double', 'struct',
     'else', 'enum', 'payable', 'function', 'modifier', 'emit', 'export', 'extern', 'false', 'constructor',
     'float', 'if', 'contract', 'int', 'long', 'string', 'super', 'or', 'private', 'protected', 'noReentrancy',
     'public', 'return', 'returns', 'assert', 'event', 'indexed', 'using', 'require', 'uint', 'onlyDaoChallenge',
     'transfer', 'Transfer', 'Transaction', 'switch', 'pure', 'view', 'this', 'throw', 'true', 'try', 'revert',
     'bytes', 'bytes4', 'bytes32', 'internal', 'external', 'union', 'constant', 'while', 'for', 'notExecuted',
     'NULL', 'uint256', 'uint128', 'uint8', 'uint16', 'address', 'call', 'msg', 'value', 'sender', 'notConfirmed',
     'private', 'onlyOwner', 'internal', 'onlyGovernor', 'onlyCommittee', 'onlyAdmin', 'onlyPlayers', 'ownerExists',
     'onlyManager', 'onlyHuman', 'only_owner', 'onlyCongressMembers', 'preventReentry', 'noEther', 'onlyMembers',
     'onlyProxyOwner', 'confirmed', 'mapping'})

# holds known non-user-defined functions; immutable set
main_set = frozenset({'function', 'constructor', 'modifier', 'contract'})

# arguments in main function; immutable set
main_args = frozenset({'argc', 'argv'})


def clean_fragment(fragment):
    # dictionary; map function name to symbol name + number
    fun_symbols = {}
    # dictionary; map variable name to symbol name + number
    var_symbols = {}

    fun_count = 1
    var_count = 1

    # regular expression to catch multi-line comment
    rx_comment = re.compile('\*/\s*$')
    # regular expression to find function name candidates
    rx_fun = re.compile(r'\b([_A-Za-z]\w*)\b(?=\s*\()')
    # regular expression to find variable name candidates
    # rx_var = re.compile(r'\b([_A-Za-z]\w*)\b(?!\s*\()')
    rx_var = re.compile(r'\b([_A-Za-z]\w*)\b(?:(?=\s*\w+\()|(?!\s*\w+))(?!\s*\()')

    # final cleaned gadget output to return to interface
    cleaned_fragment = []

    for line in fragment:
        # process if not the header line and not a multi-line commented line
        if rx_comment.search(line) is None:
            # remove all string literals (keep the quotes)
            nostrlit_line = re.sub(r'".*?"', '""', line)
            # remove all character literals
            nocharlit_line = re.sub(r"'.*?'", "''", nostrlit_line)
            # replace any non-ASCII characters with empty string
            ascii_line = re.sub(r'[^\x00-\x7f]', r'', nocharlit_line)

            # return, in order, all regex matches at string list; preserves order for semantics
            user_fun = rx_fun.findall(ascii_line)
            user_var = rx_var.findall(ascii_line)

            # Could easily make a "clean fragment" type class to prevent duplicate functionality
            # of creating/comparing symbol names for functions and variables in much the same way.
            # The comparison frozenset, symbol dictionaries, and counters would be class scope.
            # So would only need to pass a string list and a string literal for symbol names to
            # another function.
            for fun_name in user_fun:
                if len({fun_name}.difference(main_set)) != 0 and len({fun_name}.difference(keywords)) != 0:
                    # DEBUG
                    # print('comparing ' + str(fun_name + ' to ' + str(main_set)))
                    # print(fun_name + ' diff len from main is ' + str(len({fun_name}.difference(main_set))))
                    # print('comparing ' + str(fun_name + ' to ' + str(keywords)))
                    # print(fun_name + ' diff len from keywords is ' + str(len({fun_name}.difference(keywords))))
                    ###
                    # check to see if function name already in dictionary
                    if fun_name not in fun_symbols.keys():
                        fun_symbols[fun_name] = 'FUN' + str(fun_count)
                        fun_count += 1
                    # ensure that only function name gets replaced (no variable name with same
                    # identifier); uses positive lookforward
                    ascii_line = re.sub(r'\b(' + fun_name + r')\b(?=\s*\()', fun_symbols[fun_name], ascii_line)

            for var_name in user_var:
                # next line is the nuanced difference between fun_name and var_name
                if len({var_name}.difference(keywords)) != 0 and len({var_name}.difference(main_args)) != 0:
                    # DEBUG
                    # print('comparing ' + str(var_name + ' to ' + str(keywords)))
                    # print(var_name + ' diff len from keywords is ' + str(len({var_name}.difference(keywords))))
                    # print('comparing ' + str(var_name + ' to ' + str(main_args)))
                    # print(var_name + ' diff len from main args is ' + str(len({var_name}.difference(main_args))))
                    ###
                    # check to see if variable name already in dictionary
                    if var_name not in var_symbols.keys():
                        var_symbols[var_name] = 'VAR' + str(var_count)
                        var_count += 1
                    # ensure that only variable name gets replaced (no function name with same
                    # identifier; uses negative lookforward
                    ascii_line = re.sub(r'\b(' + var_name + r')\b(?:(?=\s*\w+\()|(?!\s*\w+))(?!\s*\()', \
                                        var_symbols[var_name], ascii_line)

            cleaned_fragment.append(ascii_line)
    # return the list of cleaned lines
    return cleaned_fragment


def remove_begginer_space(contract):
    # Split the text into lines and remove leading spaces
    lines = [line.lstrip() for line in contract.splitlines()]

    # Join the lines back into a single text
    cleaned_text = '\n'.join(lines)
    return cleaned_text


def remove_version(contract_text):
    # Remove solidity version pragma
    res = re.sub(r'pragma solidity\s+\^?\d+\.\d+\.\d+;', '', contract_text)
    res = '\n'.join([line for line in res.split('\n') if 'pragma solidity' not in line])
    return res


def remove_black_lines(contract):
    solidity_code = '\n'.join([line for line in contract.split('\n') if line.strip() != ''])
    solidity_code = '\n'.join(line for line in solidity_code.split('\n') if line.strip())
    solidity_code = '\n'.join(line for line in solidity_code.split('\n') if not line.isspace())
    return solidity_code


def remove_comments_and_non_ascii(contract):
    contract = re.sub(r'\/\*[\s\S]*?\*\/|\/\/[^\n]*', '', contract)
    contract = re.sub(r'\/\/.*', '', contract)  # Remove comments
    contract = re.sub(r'[^\x00-\x7F]+', '', contract)
    contract = ''.join([i if ord(i) < 128 else ' ' for i in contract])

    return contract


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


def run_task_06(contract):
    frgs = []
    contract = remove_version(contract)
    contract = remove_comments_and_non_ascii(contract)
    contract = remove_begginer_space(contract)
    contract = remove_black_lines(contract)
    contract = rename_user_defined_identifiers(contract)
    segments = contract.strip().split('\n')
    fragments = clean_fragment(segments)
    # for fragment in fragments:
    #     frg = tokenize(fragment)
    #     # print(frg)
    #     frgs.append(frg)
        # print("--------------------------------------------------------------")

    return fragments


def run_task_04(contract):
    frgs = []
    contract = remove_version(contract)
    contract = remove_comments_and_non_ascii(contract)
    contract = remove_begginer_space(contract)
    contract = remove_black_lines(contract)
    contract = rename_user_defined_identifiers(contract)
    segments = contract.strip().split('\n')
    fragments = clean_fragment(segments)
    for fragment in fragments:
        frg = tokenize(fragment)
        # print(frg)
        frgs.append(frg)
        # print("--------------------------------------------------------------")

    return frgs



    # def run_task_05(contract):
    # frgms = []
    # contract = remove_version(contract)
    # contract = remove_comments_and_non_ascii(contract)
    # contract = remove_begginer_space(contract)
    # contract = remove_black_lines(contract)
    # contract = rename_user_defined_identifiers(contract)
    # segments = contract.strip().split('\n')
    # fragments = clean_fragment(segments)
    # for fragment in fragments:
    #     frg = tokenize(fragment)
    #     # print(frg)
    #     frgms.append(frg)
    #     # print("--------------------------------------------------------------")
    #
    # return frgms
