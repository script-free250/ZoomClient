import os
import shutil
import base64
import customtkinter as ctk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# --- تعريف أنواع التشفير ---
MODE_PASSWORD_ONLY = b'\x01'
MODE_PASSWORD_AND_KEY = b'\x02'

# --- إعدادات الواجهة ---
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("green")

class FinalEncryptorApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("FileFortress - التشفير النهائي")
        self.geometry("600x500")

        self.header_label = ctk.CTkLabel(self, text="FileFortress", font=ctk.CTkFont(size=24, weight="bold"))
        self.header_label.pack(pady=10)

        self.tabview = ctk.CTkTabview(self, width=580, height=420)
        self.tabview.pack(padx=10, pady=5)
        self.encrypt_tab = self.tabview.add("🔒 تشفير")
        self.decrypt_tab = self.tabview.add("🔑 فك تشفير")

        self.setup_encrypt_tab()
        self.setup_decrypt_tab()
        
        self.source_folder = ""
        self.locked_file = ""
        self.key_file = ""
        self.decryption_mode = None

    def setup_encrypt_tab(self):
        self.select_folder_button = ctk.CTkButton(self.encrypt_tab, text="1. اختر المجلد المراد تشفيره", command=self.select_folder_to_encrypt)
        self.select_folder_button.pack(pady=15, padx=20, fill="x")
        self.folder_label = ctk.CTkLabel(self.encrypt_tab, text="لم يتم اختيار أي مجلد", text_color="gray")
        self.folder_label.pack(pady=5)

        self.password_entry_encrypt = ctk.CTkEntry(self.encrypt_tab, placeholder_text="2. أدخل كلمة مرور قوية", show="*")
        self.password_entry_encrypt.pack(pady=15, padx=20, fill="x")

        self.use_keyfile_check = ctk.CTkCheckBox(self.encrypt_tab, text="استخدام أمان إضافي (كلمة مرور + ملف مفتاح)")
        self.use_keyfile_check.pack(pady=10, padx=20)
        self.use_keyfile_check.select() # تفعيل الخيار افتراضيًا

        self.encrypt_button = ctk.CTkButton(self.encrypt_tab, text="🔒 ابدأ التشفير الآن", height=40, command=self.encrypt_folder_action)
        self.encrypt_button.pack(pady=20, padx=20, fill="x")

    def setup_decrypt_tab(self):
        self.select_file_button = ctk.CTkButton(self.decrypt_tab, text="1. اختر الملف المشفر (.locked)", command=self.select_file_to_decrypt)
        self.select_file_button.pack(pady=10, padx=20, fill="x")
        self.locked_file_label = ctk.CTkLabel(self.decrypt_tab, text="لم يتم اختيار ملف", text_color="gray")
        self.locked_file_label.pack(pady=(0, 10))

        self.select_key_button = ctk.CTkButton(self.decrypt_tab, text="2. اختر ملف المفتاح (.key)", command=self.select_key_file)
        self.select_key_button.pack(pady=10, padx=20, fill="x")
        self.key_file_label = ctk.CTkLabel(self.decrypt_tab, text="لم يتم اختيار مفتاح", text_color="gray")
        self.key_file_label.pack(pady=(0, 10))

        self.password_entry_decrypt = ctk.CTkEntry(self.decrypt_tab, placeholder_text="3. أدخل كلمة المرور", show="*")
        self.password_entry_decrypt.pack(pady=10, padx=20, fill="x")
        
        self.decrypt_button = ctk.CTkButton(self.decrypt_tab, text="🔑 فك التشفير", height=40, command=self.decrypt_folder_action)
        self.decrypt_button.pack(pady=15, padx=20, fill="x")

    def select_folder_to_encrypt(self):
        path = filedialog.askdirectory(title="اختر المجلد الذي تريد تشفيره")
        if path:
            self.source_folder = path
            self.folder_label.configure(text=os.path.basename(path))

    def select_file_to_decrypt(self):
        path = filedialog.askopenfilename(title="اختر الملف المشفر", filetypes=[("Locked Files", "*.locked")])
        if not path: return
        
        self.locked_file = path
        self.locked_file_label.configure(text=os.path.basename(path))
        
        # --- الذكاء في فك التشفير ---
        with open(path, 'rb') as f:
            mode_header = f.read(1)
        
        if mode_header == MODE_PASSWORD_ONLY:
            self.decryption_mode = "password_only"
            self.select_key_button.configure(state="disabled") # تعطيل زر المفتاح
            self.key_file_label.configure(text="فك التشفير بكلمة المرور فقط")
        elif mode_header == MODE_PASSWORD_AND_KEY:
            self.decryption_mode = "password_and_key"
            self.select_key_button.configure(state="normal") # تفعيل زر المفتاح
            self.key_file_label.configure(text="لم يتم اختيار مفتاح")
        else:
            messagebox.showerror("خطأ", "ملف مشفر غير معروف أو تالف.")
            self.decryption_mode = None

    def select_key_file(self):
        path = filedialog.askopenfilename(title="اختر ملف المفتاح الخاص بك", filetypes=[("Key Files", "*.key")])
        if path:
            self.key_file = path
            self.key_file_label.configure(text=os.path.basename(path))

    def get_encryption_key(self, password, salt, key_file_content=None):
        base_secret = password.encode()
        if key_file_content:
            base_secret += key_file_content
            
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600000)
        return base64.urlsafe_b64encode(kdf.derive(base_secret))

    def encrypt_folder_action(self):
        if not self.source_folder or not self.password_entry_encrypt.get():
            messagebox.showerror("خطأ", "الرجاء اختيار مجلد وإدخال كلمة مرور.")
            return

        password = self.password_entry_encrypt.get()
        use_keyfile = self.use_keyfile_check.get()
        key_file_content = None
        mode_header = MODE_PASSWORD_ONLY

        if use_keyfile:
            key_file_path = filedialog.asksaveasfilename(defaultextension=".key", filetypes=[("Key Files", "*.key")], title="احفظ ملف المفتاح في مكان آمن")
            if not key_file_path:
                messagebox.showwarning("تنبيه", "تم إلغاء عملية التشفير.")
                return
            key_file_content = os.urandom(32)
            with open(key_file_path, 'wb') as kf:
                kf.write(key_file_content)
            mode_header = MODE_PASSWORD_AND_KEY
        
        temp_zip_path = shutil.make_archive("temp_archive", 'zip', self.source_folder)
        
        salt = os.urandom(16)
        encryption_key = self.get_encryption_key(password, salt, key_file_content)
        fernet = Fernet(encryption_key)
        
        with open(temp_zip_path, 'rb') as f:
            zip_data = f.read()
        encrypted_data = fernet.encrypt(zip_data)
        
        output_path = self.source_folder + ".locked"
        with open(output_path, 'wb') as f:
            f.write(mode_header) # كتابة نوع التشفير أولاً
            f.write(salt)
            f.write(encrypted_data)
            
        os.remove(temp_zip_path)
        
        messagebox.showinfo("نجاح!", "✅ تم تشفير المجلد بنجاح!")
        
        # --- سؤال الحذف التلقائي ---
        if messagebox.askyesno("تأكيد الحذف", "هل تريد حذف المجلد الأصلي غير المشفر الآن؟\n\n🚨 تحذير: هذا الإجراء لا يمكن التراجع عنه."):
            try:
                shutil.rmtree(self.source_folder)
                messagebox.showinfo("تم الحذف", "تم حذف المجلد الأصلي بنجاح.")
            except Exception as e:
                messagebox.showerror("خطأ أثناء الحذف", f"لم نتمكن من حذف المجلد الأصلي.\nالخطأ: {e}")


    def decrypt_folder_action(self):
        if not self.locked_file or not self.password_entry_decrypt.get():
            messagebox.showerror("خطأ", "الرجاء اختيار ملف وإدخال كلمة مرور.")
            return

        key_file_content = None
        if self.decryption_mode == "password_and_key":
            if not self.key_file:
                messagebox.showerror("خطأ", "هذا الملف يتطلب ملف مفتاح لفك تشفيره.")
                return
            with open(self.key_file, 'rb') as kf:
                key_file_content = kf.read()
        
        try:
            password = self.password_entry_decrypt.get()
            with open(self.locked_file, 'rb') as f:
                f.read(1) # تخطي الهيدر
                salt = f.read(16)
                encrypted_data = f.read()

            encryption_key = self.get_encryption_key(password, salt, key_file_content)
            fernet = Fernet(encryption_key)
            decrypted_zip_data = fernet.decrypt(encrypted_data)

            temp_zip_path = "decrypted_temp.zip"
            with open(temp_zip_path, 'wb') as f:
                f.write(decrypted_zip_data)
            
            output_folder_path = self.locked_file.replace(".locked", "")
            shutil.unpack_archive(temp_zip_path, output_folder_path, 'zip')

            os.remove(temp_zip_path)
            
            messagebox.showinfo("نجاح!", f"✅ تم فك تشفير المجلد بنجاح!\n\nتم حفظ الملفات في:\n{output_folder_path}")
        except Exception as e:
            messagebox.showerror("فشل فك التشفير", "فشلت العملية. الأسباب المحتملة:\n\n- كلمة المرور غير صحيحة.\n- ملف المفتاح غير صحيح (إن وجد).\n- الملف المشفر تالف.")

if __name__ == "__main__":
    app = FinalEncryptorApp()
    app.mainloop()
