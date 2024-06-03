import re


# keywords of solidity; immutable set
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


# input is a list of string lines
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

def minify_solidity_code(code):
    # حذف کامنت‌های چند خطی
    code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
    # حذف کامنت‌های تک خطی
    code = re.sub(r'//.*', '', code)
    # حذف فضاهای اضافی و خطوط جدید بین عبارات، با حفظ رشته‌ها و محتوای داخل آنها
    code = re.sub(r'\s+', ' ', code)  # جایگزینی تمام whitespace ها با یک فضای خالی
    code = re.sub(r'\s*;\s*', ';', code)  # حذف فضاهای اضافی دور نقطه‌ویرگول
    code = re.sub(r'\s*{\s*', '{', code)  # حذف فضاهای اضافی دور کروشه باز
    code = re.sub(r'\s*}\s*', '}', code)  # حذف فضاهای اضافی دور کروشه بسته
    code = re.sub(r'\s*\(\s*', '(', code)  # حذف فضاهای اضافی دور پرانتز باز
    code = re.sub(r'\s*\)\s*', ')', code)  # حذف فضاهای اضافی دور پرانتز بسته
    code = re.sub(r'\s*,\s*', ',', code)  # حذف فضاهای اضافی دور کاما
    return code.strip()

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

def remove_begginer_space(contract):
    # Split the text into lines and remove leading spaces
    lines = [line.lstrip() for line in contract.splitlines()]

    # Join the lines back into a single text
    cleaned_text = '\n'.join(lines)
    return cleaned_text
def get_fragments(contract):
    contract = remove_version(contract)
    contract = remove_comments_and_non_ascii(contract)
    contract = remove_begginer_space(contract)
    contract = remove_black_lines(contract)
    # contract = minify_solidity_code(contract)
    segments = contract.strip().split('\n')
    fragments = clean_fragment(segments)

    return fragments



