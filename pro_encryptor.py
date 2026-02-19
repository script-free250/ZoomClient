import os
import shutil
import base64
import customtkinter as ctk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# --- إعدادات الواجهة ---
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("green")

class ProEncryptorApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("FileFortress - تشفير المجلدات الاحترافي")
        self.geometry("600x450")

        self.header_label = ctk.CTkLabel(self, text="FileFortress", font=ctk.CTkFont(size=24, weight="bold"))
        self.header_label.pack(pady=10)

        self.tabview = ctk.CTkTabview(self, width=580, height=380)
        self.tabview.pack(padx=10, pady=5)

        self.encrypt_tab = self.tabview.add("🔒 تشفير مجلد")
        self.decrypt_tab = self.tabview.add("🔑 فك تشفير مجلد")

        self.setup_encrypt_tab()
        self.setup_decrypt_tab()
        
        # متغيرات لحفظ المسارات
        self.source_folder = ""
        self.locked_file = ""
        self.key_file = ""

    # --- إعداد واجهة التشفير ---
    def setup_encrypt_tab(self):
        # زر اختيار المجلد
        self.select_folder_button = ctk.CTkButton(self.encrypt_tab, text="1. اختر المجلد المراد تشفيره", command=self.select_folder_to_encrypt)
        self.select_folder_button.pack(pady=15, padx=20, fill="x")
        self.folder_label = ctk.CTkLabel(self.encrypt_tab, text="لم يتم اختيار أي مجلد", text_color="gray")
        self.folder_label.pack(pady=5)

        # حقل كلمة المرور
        self.password_entry_encrypt = ctk.CTkEntry(self.encrypt_tab, placeholder_text="2. أدخل كلمة مرور قوية", show="*")
        self.password_entry_encrypt.pack(pady=15, padx=20, fill="x")
        
        # زر بدء التشفير
        self.encrypt_button = ctk.CTkButton(self.encrypt_tab, text="🔒 ابدأ التشفير الآن", height=40, command=self.encrypt_folder_action)
        self.encrypt_button.pack(pady=20, padx=20, fill="x")

    # --- إعداد واجهة فك التشفير ---
    def setup_decrypt_tab(self):
        # زر اختيار الملف المشفر
        self.select_file_button = ctk.CTkButton(self.decrypt_tab, text="1. اختر الملف المشفر (.locked)", command=self.select_file_to_decrypt)
        self.select_file_button.pack(pady=10, padx=20, fill="x")
        self.locked_file_label = ctk.CTkLabel(self.decrypt_tab, text="لم يتم اختيار ملف", text_color="gray")
        self.locked_file_label.pack(pady=(0, 10))

        # زر اختيار ملف المفتاح
        self.select_key_button = ctk.CTkButton(self.decrypt_tab, text="2. اختر ملف المفتاح (.key)", command=self.select_key_file)
        self.select_key_button.pack(pady=10, padx=20, fill="x")
        self.key_file_label = ctk.CTkLabel(self.decrypt_tab, text="لم يتم اختيار مفتاح", text_color="gray")
        self.key_file_label.pack(pady=(0, 10))

        # حقل كلمة المرور
        self.password_entry_decrypt = ctk.CTkEntry(self.decrypt_tab, placeholder_text="3. أدخل كلمة المرور", show="*")
        self.password_entry_decrypt.pack(pady=10, padx=20, fill="x")
        
        # زر بدء فك التشفير
        self.decrypt_button = ctk.CTkButton(self.decrypt_tab, text="🔑 فك التشفير", height=40, command=self.decrypt_folder_action)
        self.decrypt_button.pack(pady=15, padx=20, fill="x")

    # --- دوال اختيار الملفات والمجلدات ---
    def select_folder_to_encrypt(self):
        path = filedialog.askdirectory(title="اختر المجلد الذي تريد تشفيره")
        if path:
            self.source_folder = path
            self.folder_label.configure(text=os.path.basename(path))

    def select_file_to_decrypt(self):
        path = filedialog.askopenfilename(title="اختر الملف المشفر", filetypes=[("Locked Files", "*.locked")])
        if path:
            self.locked_file = path
            self.locked_file_label.configure(text=os.path.basename(path))

    def select_key_file(self):
        path = filedialog.askopenfilename(title="اختر ملف المفتاح الخاص بك", filetypes=[("Key Files", "*.key")])
        if path:
            self.key_file = path
            self.key_file_label.configure(text=os.path.basename(path))

    # --- دوال التشفير وفك التشفير الرئيسية ---
    def get_encryption_key(self, password, salt, key_file_content):
        combined_secret = password.encode() + key_file_content
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=600000,
        )
        return base64.urlsafe_b64encode(kdf.derive(combined_secret))

    def encrypt_folder_action(self):
        if not self.source_folder or not self.password_entry_encrypt.get():
            messagebox.showerror("خطأ", "الرجاء اختيار مجلد وإدخال كلمة مرور.")
            return
        
        # 1. إنشاء ملف المفتاح
        key_file_path = filedialog.asksaveasfilename(defaultextension=".key", filetypes=[("Key Files", "*.key")], title="احفظ ملف المفتاح في مكان آمن")
        if not key_file_path:
            messagebox.showwarning("تنبيه", "تم إلغاء عملية التشفير.")
            return
        
        key_file_content = os.urandom(32) # 32 بايت من البيانات العشوائية الآمنة
        with open(key_file_path, 'wb') as kf:
            kf.write(key_file_content)

        # 2. ضغط المجلد في ملف zip مؤقت
        temp_zip_path = shutil.make_archive("temp_archive", 'zip', self.source_folder)
        
        # 3. تشفير ملف الـ zip
        password = self.password_entry_encrypt.get()
        salt = os.urandom(16)
        encryption_key = self.get_encryption_key(password, salt, key_file_content)
        fernet = Fernet(encryption_key)
        
        with open(temp_zip_path, 'rb') as f:
            zip_data = f.read()
        encrypted_data = fernet.encrypt(zip_data)
        
        # 4. حفظ الملف النهائي .locked (salt + data)
        output_path = self.source_folder + ".locked"
        with open(output_path, 'wb') as f:
            f.write(salt)
            f.write(encrypted_data)
        
        # 5. تنظيف الملفات المؤقتة
        os.remove(temp_zip_path)

        messagebox.showinfo("نجاح!", f"✅ تم تشفير المجلد بنجاح!\n\nتم حفظ الملف المشفر في:\n{output_path}\n\nتم حفظ ملف المفتاح في:\n{key_file_path}\n\n🚨 تحذير: احتفظ بملف المفتاح وكلمة المرور، بدونهما لن تتمكن من استعادة ملفاتك أبدًا!")

    def decrypt_folder_action(self):
        if not self.locked_file or not self.key_file or not self.password_entry_decrypt.get():
            messagebox.showerror("خطأ", "الرجاء اختيار الملف المشفر، ملف المفتاح، وإدخال كلمة المرور.")
            return

        try:
            # 1. قراءة الملفات المطلوبة
            password = self.password_entry_decrypt.get()
            with open(self.key_file, 'rb') as kf:
                key_file_content = kf.read()
            
            with open(self.locked_file, 'rb') as f:
                salt = f.read(16)
                encrypted_data = f.read()

            # 2. إعادة توليد مفتاح التشفير ومحاولة فك التشفير
            encryption_key = self.get_encryption_key(password, salt, key_file_content)
            fernet = Fernet(encryption_key)
            decrypted_zip_data = fernet.decrypt(encrypted_data)

            # 3. حفظ وفك ضغط ملف الـ zip
            temp_zip_path = "decrypted_temp.zip"
            with open(temp_zip_path, 'wb') as f:
                f.write(decrypted_zip_data)
            
            output_folder_path = self.locked_file.replace(".locked", "_decrypted")
            shutil.unpack_archive(temp_zip_path, output_folder_path)

            # 4. تنظيف
            os.remove(temp_zip_path)
            
            messagebox.showinfo("نجاح!", f"✅ تم فك تشفير المجلد بنجاح!\n\nتم حفظ الملفات في مجلد:\n{output_folder_path}")

        except Exception as e:
            messagebox.showerror("فشل فك التشفير", "فشلت العملية. الأسباب المحتملة:\n\n- كلمة المرور غير صحيحة.\n- ملف المفتاح غير صحيح.\n- الملف المشفر تالف.")

if __name__ == "__main__":
    app = ProEncryptorApp()
    app.mainloop()

