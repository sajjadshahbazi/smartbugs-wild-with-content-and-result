"""
Preprocessing utilities for Solidity smart contract source code.

Pipeline used by get_fragments():
  1. Split the contract into lines.
  2. For each line, strip string/char literals and non-ASCII characters.
  3. Replace user-defined function names with FUN<N> and user-defined
     variable names with VAR<N>, leaving Solidity keywords untouched.

clean_smart_contract() performs the earlier, whole-contract steps
(removing the pragma line, comments, and non-ASCII characters) before
get_fragments() is called.
"""

import re

# Solidity keywords and common built-in identifiers that must never be
# replaced with FUN<N>/VAR<N> placeholders.
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
     'onlyProxyOwner', 'confirmed', 'mapping'}
)

# Built-in declaration keywords that introduce a function definition and
# must not be treated as a user-defined function name themselves.
main_set = frozenset({'function', 'constructor', 'modifier', 'contract'})

# Standard "main" arguments that should not be replaced with VAR<N>.
main_args = frozenset({'argc', 'argv'})


def clean_fragment_without_remove_line(fragment):
    """
    Replace user-defined function names with FUN<N> and user-defined
    variable names with VAR<N>, one line at a time. Line count is
    preserved (no lines are dropped), which keeps line numbers aligned
    with the vulnerable-line information collected elsewhere in the
    pipeline.

    :param fragment: list of source lines (already pragma/comment free)
    :return: list of lines with identifiers replaced by placeholders
    """
    fun_symbols = {}
    var_symbols = {}
    fun_count = 1
    var_count = 1

    # Matches an identifier immediately followed by "(" -> function call/def
    rx_fun = re.compile(r'\b([_A-Za-z]\w*)\b(?=\s*\()')
    # Matches an identifier that is NOT immediately followed by "(" -> variable
    rx_var = re.compile(r'\b([_A-Za-z]\w*)\b(?:(?=\s*\w+\()|(?!\s*\w+))(?!\s*\()')

    cleaned_fragment = []

    for line in fragment:
        # Strip string/char literals and non-ASCII characters first, so
        # identifier matching below only sees real code tokens.
        nostrlit_line = re.sub(r'".*?"', '""', line)
        nocharlit_line = re.sub(r"'.*?'", "''", nostrlit_line)
        ascii_line = re.sub(r'[^\x00-\x7f]', r'', nocharlit_line)

        user_fun = rx_fun.findall(ascii_line)
        user_var = rx_var.findall(ascii_line)

        # Replace user-defined function names with FUN<N>
        for fun_name in user_fun:
            if len({fun_name}.difference(main_set)) != 0 and len({fun_name}.difference(keywords)) != 0:
                if fun_name not in fun_symbols:
                    fun_symbols[fun_name] = 'FUN' + str(fun_count)
                    fun_count += 1
                ascii_line = re.sub(r'\b(' + fun_name + r')\b(?=\s*\()', fun_symbols[fun_name], ascii_line)

        # Replace user-defined variable names with VAR<N>
        for var_name in user_var:
            if len({var_name}.difference(keywords)) != 0 and len({var_name}.difference(main_args)) != 0:
                if var_name not in var_symbols:
                    var_symbols[var_name] = 'VAR' + str(var_count)
                    var_count += 1
                ascii_line = re.sub(
                    r'\b(' + var_name + r')\b(?:(?=\s*\w+\()|(?!\s*\w+))(?!\s*\()',
                    var_symbols[var_name], ascii_line
                )

        cleaned_fragment.append(ascii_line)

    return cleaned_fragment


def remove_version_without_remove_line(contract_text):
    """Remove the `pragma solidity ...;` declaration, replacing it with
    an empty line so downstream line numbers stay unaffected."""
    res = re.sub(r'pragma solidity\s+\^?\d+\.\d+\.\d+;', '', contract_text)
    res = '\n'.join([line if 'pragma solidity' not in line else '' for line in res.split('\n')])
    return res


def remove_black_lines_without_remove_line(contract):
    """Strip leading/trailing whitespace from every line while keeping
    the total number of lines unchanged."""
    return '\n'.join([line.strip() for line in contract.split('\n')])


def remove_comments_and_non_ascii_without_removing_lines(contract):
    """Remove single-line and multi-line comments, and drop non-ASCII
    characters, without changing the line count (multi-line comments are
    replaced by the same number of blank lines they originally spanned)."""
    contract = re.sub(r'\/\*[\s\S]*?\*\/', lambda match: '\n' * match.group(0).count('\n'), contract)
    contract = re.sub(r'\/\/[^\n]*', '', contract)
    contract = ''.join([i if ord(i) < 128 else '' for i in contract])
    return contract


def remove_begginer_space(contract):
    """Remove leading whitespace from every line."""
    lines = [line.lstrip() for line in contract.splitlines()]
    return '\n'.join(lines)


def clean_smart_contract(contract):
    """Whole-contract preprocessing: strip the pragma line, comments,
    non-ASCII characters, and leading whitespace. Line numbers are
    preserved throughout so vulnerable-line data stays valid."""
    contract = remove_version_without_remove_line(contract)
    contract = remove_comments_and_non_ascii_without_removing_lines(contract)
    contract = remove_begginer_space(contract)
    contract = remove_black_lines_without_remove_line(contract)
    return contract


def get_fragments(contract):
    """Split a preprocessed contract into per-line fragments with
    function/variable names replaced by FUN<N>/VAR<N> placeholders."""
    segments = contract.split('\n')
    return clean_fragment_without_remove_line(segments)
