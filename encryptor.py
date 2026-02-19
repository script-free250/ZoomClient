import os
import base64
import argparse
from getpass import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def generate_key_from_password(password: str, salt: bytes) -> bytes:
    """
    يولّد مفتاح تشفير آمن من كلمة المرور والـ salt.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def encrypt_file(file_path: str, password: str):
    """
    يشفر ملفًا باستخدام كلمة مرور.
    """
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
    except FileNotFoundError:
        print(f"خطأ: لم يتم العثور على الملف '{file_path}'")
        return

    # إنشاء salt عشوائي وآمن
    salt = os.urandom(16)
    key = generate_key_from_password(password, salt)
    
    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(data)

    # كتابة الـ salt مع البيانات المشفرة في ملف جديد
    encrypted_file_path = file_path + ".encrypted"
    with open(encrypted_file_path, 'wb') as f:
        f.write(salt)
        f.write(encrypted_data)
    
    print(f"✅ تم تشفير الملف بنجاح وحفظه في: {encrypted_file_path}")
    # حذف الملف الأصلي لمزيد من الأمان (اختياري)
    # os.remove(file_path)

def decrypt_file(file_path: str, password: str):
    """
    يفك تشفير ملف باستخدام كلمة مرور.
    """
    try:
        with open(file_path, 'rb') as f:
            # قراءة الـ salt (أول 16 بايت)
            salt = f.read(16)
            encrypted_data = f.read()
    except FileNotFoundError:
        print(f"خطأ: لم يتم العثور على الملف '{file_path}'")
        return

    key = generate_key_from_password(password, salt)
    fernet = Fernet(key)

    try:
        decrypted_data = fernet.decrypt(encrypted_data)
    except Exception as e:
        print("❌ خطأ: كلمة المرور غير صحيحة أو الملف تالف.")
        return

    # تحديد مسار الملف الأصلي
    decrypted_file_path = file_path.replace(".encrypted", "")
    with open(decrypted_file_path, 'wb') as f:
        f.write(decrypted_data)
        
    print(f"✅ تم فك تشفير الملف بنجاح وحفظه في: {decrypted_file_path}")

def main():
    parser = argparse.ArgumentParser(description="برنامج لتشفير وفك تشفير الملفات.")
    parser.add_argument("file", help="مسار الملف المطلوب.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-e", "--encrypt", action="store_true", help="لتشفير الملف.")
    group.add_argument("-d", "--decrypt", action="store_true", help="لفك تشفير الملف.")

    args = parser.parse_args()

    password = getpass("الرجاء إدخال كلمة المرور: ")

    if args.encrypt:
        encrypt_file(args.file, password)
    elif args.decrypt:
        decrypt_file(args.file, password)

if __name__ == "__main__":
    main()
