import os
import subprocess


def get_bytecode(file_path):
    """
    این تابع بایت‌کد یک فایل قرارداد هوشمند را استخراج می‌کند.
    :param file_path: مسیر فایل قرارداد هوشمند
    :return: بایت‌کد (opcode_sequence) قرارداد هوشمند
    """
    try:
        # فراخوانی solc برای استخراج بایت‌کد
        bytecode = subprocess.check_output(['solc', '--bin', file_path])

        # پردازش خروجی و استخراج بایت‌کد
        bytecode_str = bytecode.decode().split('===')[1].strip()

        return bytecode_str
    except subprocess.CalledProcessError as e:
        print(f"خطا در استخراج بایت‌کد برای فایل {file_path}: {e}")
        return None


def process_directory(directory):
    """
    این تابع تمام فایل‌های قرارداد هوشمند را در یک پوشه پردازش می‌کند و بایت‌کد آن‌ها را استخراج می‌کند.
    :param directory: مسیر پوشه حاوی فایل‌های قرارداد هوشمند
    """
    bytecodes = []
    print(f"01 {directory}")
    for root, dirs, files in os.walk(directory):
        print(f"02 ")
        for file in files:
            print(f"03 ")
            if file.endswith('.sol'):
                print(f"04 ")
                file_path = os.path.join(root, file)
                bytecode = get_bytecode(file_path)
                if bytecode:
                    bytecodes.append(bytecode)

    return bytecodes


# استفاده از تابع process_directory
ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), '..'))
directory_path = f"{ROOT}\\contract\\"
print(f"vffffffffff {os.path.isdir(directory_path)}")
bytecodes = process_directory(directory_path)

# چاپ بایت‌کدها
for bytecode in bytecodes:
    print(bytecode)