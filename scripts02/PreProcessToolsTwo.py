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


def clean_fragment_without_remove_line(fragment):
    # دیکشنری برای نگاشت نام توابع به نمادها
    fun_symbols = {}
    # دیکشنری برای نگاشت نام متغیرها به نمادها
    var_symbols = {}

    fun_count = 1
    var_count = 1

    # الگوی منظم برای تشخیص پایان نظرات چند خطی
    rx_comment = re.compile('\*/\s*$')
    # الگوی منظم برای یافتن نام‌های تابع
    rx_fun = re.compile(r'\b([_A-Za-z]\w*)\b(?=\s*\()')
    # الگوی منظم برای یافتن نام‌های متغیر
    rx_var = re.compile(r'\b([_A-Za-z]\w*)\b(?:(?=\s*\w+\()|(?!\s*\w+))(?!\s*\()')

    # خروجی نهایی برای بازگرداندن
    cleaned_fragment = []

    for line in fragment:
        # حذف نظرات چند خطی و کاراکترهای غیر ASCII
        nostrlit_line = re.sub(r'".*?"', '""', line)
        nocharlit_line = re.sub(r"'.*?'", "''", nostrlit_line)
        ascii_line = re.sub(r'[^\x00-\x7f]', r'', nocharlit_line)

        # یافتن نام‌های تابع و متغیر
        user_fun = rx_fun.findall(ascii_line)
        user_var = rx_var.findall(ascii_line)

        # جایگزینی نام‌های تابع با نمادها
        for fun_name in user_fun:
            if len({fun_name}.difference(main_set)) != 0 and len({fun_name}.difference(keywords)) != 0:
                if fun_name not in fun_symbols:
                    fun_symbols[fun_name] = 'FUN' + str(fun_count)
                    fun_count += 1
                ascii_line = re.sub(r'\b(' + fun_name + r')\b(?=\s*\()', fun_symbols[fun_name], ascii_line)

        # جایگزینی نام‌های متغیر با نمادها
        for var_name in user_var:
            if len({var_name}.difference(keywords)) != 0 and len({var_name}.difference(main_args)) != 0:
                if var_name not in var_symbols:
                    var_symbols[var_name] = 'VAR' + str(var_count)
                    var_count += 1
                ascii_line = re.sub(r'\b(' + var_name + r')\b(?:(?=\s*\w+\()|(?!\s*\w+))(?!\s*\()', var_symbols[var_name], ascii_line)

        # اطمینان از اینکه خط به لیست نهایی اضافه شود
        cleaned_fragment.append(ascii_line)

    # بازگرداندن لیست خطوط پردازش شده
    return cleaned_fragment


def remove_version_without_remove_line(contract_text):
    # حذف عبارت نسخه Solidity بدون حذف خط
    res = re.sub(r'pragma solidity\s+\^?\d+\.\d+\.\d+;', '', contract_text)

    # جایگزین کردن خطی که pragma solidity در آن وجود دارد با خط خالی
    res = '\n'.join([line if 'pragma solidity' not in line else '' for line in res.split('\n')])

    return res

def remove_black_lines_without_remove_line(contract):
    # حذف فضای خالی از ابتدا و انتهای هر خط، اما حفظ خط‌های خالی
    solidity_code = '\n'.join([line.strip() for line in contract.split('\n')])

    return solidity_code

def remove_multiline_comments_keep_lines(contract):
    # این الگو به دنبال کامنت‌های چند خطی می‌گردد
    pattern = re.compile(r'\/\*[\s\S]*?\*\/')

    def replace_with_blank_lines(match):
        # شمارش تعداد خطوط در کامنت
        lines = match.group(0).splitlines()
        # بازگشت به همان تعداد خطوط خالی
        return '\n' * (len(lines) - 1)

    # جایگزینی متن کامنت با خطوط خالی
    contract = re.sub(pattern, replace_with_blank_lines, contract)
    return contract

def remove_singleline_comments_without_removing_lines(contract):
    # حذف محتوای کامنت‌های تک‌خطی بدون حذف خطوط آن‌ها
    contract = re.sub(r'\/\/[^\n]*', '', contract)
    return contract

def remove_comments_and_non_ascii_without_removing_lines(contract):
    # حذف نظرات چندخطی بدون حذف خطوط آن‌ها
    contract = re.sub(r'\/\*[\s\S]*?\*\/', lambda match: '\n' * match.group(0).count('\n'), contract)

    # حذف نظرات تک‌خطی بدون حذف خطوط آن‌ها
    contract = re.sub(r'\/\/[^\n]*', '', contract)

    # حذف کاراکترهای غیر ASCII بدون حذف خطوط
    contract = ''.join([i if ord(i) < 128 else '' for i in contract])

    return contract


# def remove_multiline_comments(contract):
#     # حذف محتوای کامنت‌های چند خطی و جایگزین کردن آن‌ها با خطوط خالی
#     return re.sub(r'/\*[\s\S]*?\*/', lambda match: '\n' * (match.group().count('\n') + 1), contract)


# def remove_singleline_comments(contract):
#     # حذف کامنت‌های تک خطی اما حفظ خطوط خالی
#     return re.sub(r'//[^\n]*', '', contract)
#
#
# def remove_non_ascii(contract):
#     # حذف کاراکترهای غیر ASCII اما حفظ خطوط خالی
#     return re.sub(r'[^\x00-\x7F]', '', contract)
#
#
# def clean_spaces(contract):
#     # حذف فضای خالی از ابتدا و انتهای هر خط اما حفظ خطوط خالی
#     return '\n'.join(line.strip() for line in contract.splitlines())
#
#
# def process_contract(contract):
#     # حذف کامنت‌های چند خطی
#     contract = remove_multiline_comments(contract)
#     # حذف کامنت‌های تک خطی
#     contract = remove_singleline_comments(contract)
#     # حذف کاراکترهای غیر ASCII
#     contract = remove_non_ascii(contract)
#     # حذف فضای خالی از ابتدا و انتهای خطوط
#     contract = clean_spaces(contract)
#
#     return contract

# def remove_comments_and_non_ascii_without_remove_line(contract):
#     # حذف نظرات چند خطی و تک خطی بدون حذف خود خط
#     contract = re.sub(r'\/\*[\s\S]*?\*\/', '', contract)
#     contract = re.sub(r'\/\/[^\n]*', '', contract)
#
#     # حذف کاراکترهای غیر ASCII بدون حذف خود خط
#     contract = re.sub(r'[^\x00-\x7F]+', '', contract)
#
#     # حذف تمامی کاراکترهای غیر ASCII بدون اضافه کردن فاصله
#     contract = ''.join([i if ord(i) < 128 else '' for i in contract])
#
#     return contract

def remove_begginer_space(contract):
    # Split the text into lines and remove leading spaces
    lines = [line.lstrip() for line in contract.splitlines()]

    # Join the lines back into a single text
    cleaned_text = '\n'.join(lines)
    return cleaned_text

def get_fragments(contract):
    contract = remove_version_without_remove_line(contract)
    contract = remove_comments_and_non_ascii_without_removing_lines(contract)
    contract = remove_begginer_space(contract)
    contract = remove_black_lines_without_remove_line(contract)
    segments = contract.split('\n')
    fragments = clean_fragment_without_remove_line(segments)

    return fragments
