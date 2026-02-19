import os
import shutil
import base64
import customtkinter as ctk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import sys

# --- تعريف أنواع التشفير (للتوافق المستقبلي) ---
MODE_PASSWORD_ONLY = b'\x01'
MODE_PASSWORD_AND_KEY = b'\x02'

# --- إعدادات الواجهة ---
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class GodModeEncryptor(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("FileFortress - God Mode")
        self.geometry("650x550")

        # --- إضافة أيقونة للبرنامج ---
        try:
            # يجب أن يكون ملف icon.ico في نفس مجلد البرنامج
            icon_path = self.resource_path("icon.ico")
            self.iconbitmap(icon_path)
        except Exception as e:
            print(f"Warning: Could not load icon.ico. {e}")

        # --- تصميم الواجهة ---
        self.grid_columnconfigure(0, weight=1)
        
        self.header_label = ctk.CTkLabel(self, text="FileFortress", font=ctk.CTkFont(size=30, weight="bold"))
        self.header_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        self.tabview = ctk.CTkTabview(self, width=620)
        self.tabview.grid(row=1, column=0, padx=10, pady=5, sticky="nsew")
        self.encrypt_tab = self.tabview.add("🔒 تشفير")
        self.decrypt_tab = self.tabview.add("🔑 فك تشفير")

        self.setup_encrypt_tab()
        self.setup_decrypt_tab()

        self.progress_bar = ctk.CTkProgressBar(self, mode='indeterminate')
        self.status_label = ctk.CTkLabel(self, text="الحالة: جاهز", text_color="gray")
        self.status_label.grid(row=2, column=0, padx=20, pady=10, sticky="ew")

        # متغيرات التشغيل
        self.source_path = ""
        self.locked_file = ""
        self.key_file = ""
        self.decryption_mode = None

    def resource_path(self, relative_path):
        """ Get absolute path to resource, works for dev and for PyInstaller """
        try:
            base_path = sys._MEIPASS
        except Exception:
            base_path = os.path.abspath(".")
        return os.path.join(base_path, relative_path)

    def setup_encrypt_tab(self):
        self.encrypt_tab.grid_columnconfigure(0, weight=1)
        
        self.select_button_enc = ctk.CTkButton(self.encrypt_tab, text="1. اختر مجلدًا أو ملفًا لتشفيره", command=self.select_path_to_encrypt)
        self.select_button_enc.grid(row=0, column=0, padx=20, pady=15, sticky="ew")
        self.path_label_enc = ctk.CTkLabel(self.encrypt_tab, text="لم يتم اختيار أي شيء", text_color="gray")
        self.path_label_enc.grid(row=1, column=0, padx=20)

        self.password_frame_enc = ctk.CTkFrame(self.encrypt_tab, fg_color="transparent")
        self.password_frame_enc.grid(row=2, column=0, padx=20, pady=20, sticky="ew")
        self.password_frame_enc.grid_columnconfigure(0, weight=1)
        
        self.password_entry_enc = ctk.CTkEntry(self.password_frame_enc, placeholder_text="2. أدخل كلمة مرور قوية جدًا", show="*")
        self.password_entry_enc.grid(row=0, column=0, sticky="ew")
        
        self.use_keyfile_check = ctk.CTkCheckBox(self.encrypt_tab, text="أمان إضافي (كلمة مرور + ملف مفتاح)", font=ctk.CTkFont(weight="bold"))
        self.use_keyfile_check.grid(row=3, column=0, padx=20, pady=10)
        self.use_keyfile_check.select()

        self.encrypt_button = ctk.CTkButton(self.encrypt_tab, text="🔒 ابدأ التشفير الآن", height=40, font=ctk.CTkFont(size=16, weight="bold"), command=self.encrypt_action)
        self.encrypt_button.grid(row=4, column=0, padx=20, pady=(20,10), sticky="ew")

    def setup_decrypt_tab(self):
        self.decrypt_tab.grid_columnconfigure(0, weight=1)

        self.select_file_button = ctk.CTkButton(self.decrypt_tab, text="1. اختر الملف المشفر (.locked)", command=self.select_file_to_decrypt)
        self.select_file_button.grid(row=0, column=0, padx=20, pady=15, sticky="ew")
        self.locked_file_label = ctk.CTkLabel(self.decrypt_tab, text="لم يتم اختيار ملف", text_color="gray")
        self.locked_file_label.grid(row=1, column=0, padx=20)

        self.password_frame_dec = ctk.CTkFrame(self.decrypt_tab, fg_color="transparent")
        self.password_frame_dec.grid(row=2, column=0, padx=20, pady=20, sticky="ew")
        self.password_frame_dec.grid_columnconfigure(0, weight=1)

        self.password_entry_dec = ctk.CTkEntry(self.password_frame_dec, placeholder_text="3. أدخل كلمة المرور", show="*")
        self.password_entry_dec.grid(row=0, column=0, sticky="ew")

        self.select_key_button = ctk.CTkButton(self.password_frame_dec, text="2. اختر مفتاح", width=120, command=self.select_key_file)
        self.select_key_button.grid(row=0, column=1, padx=(10, 0))

        self.key_file_label = ctk.CTkLabel(self.decrypt_tab, text="...", text_color="gray")
        self.key_file_label.grid(row=3, column=0, padx=20, pady=(0, 20))
        
        self.decrypt_button = ctk.CTkButton(self.decrypt_tab, text="🔑 فك التشفير", height=40, font=ctk.CTkFont(size=16, weight="bold"), command=self.decrypt_action)
        self.decrypt_button.grid(row=4, column=0, padx=20, pady=10, sticky="ew")

    def start_processing(self, status_text):
        self.status_label.configure(text=status_text)
        self.progress_bar.grid(row=3, column=0, padx=20, pady=(0,5), sticky="ew")
        self.progress_bar.start()
        self.update_idletasks()

    def stop_processing(self, status_text):
        self.progress_bar.stop()
        self.progress_bar.grid_forget()
        self.status_label.configure(text=status_text)

    # --- باقي الدوال المنطقية ---
    def select_path_to_encrypt(self):
        path = filedialog.askdirectory(title="اختر مجلدًا")
        if not path:
            path = filedialog.askopenfilename(title="أو اختر ملفًا واحدًا")
        if path:
            self.source_path = path
            self.path_label_enc.configure(text=os.path.basename(path))

    def select_file_to_decrypt(self):
        path = filedialog.askopenfilename(title="اختر الملف المشفر", filetypes=[("Locked Files", "*.locked")])
        if not path: return
        self.locked_file = path
        self.locked_file_label.configure(text=os.path.basename(path))
        with open(path, 'rb') as f: mode_header = f.read(1)
        if mode_header == MODE_PASSWORD_ONLY:
            self.decryption_mode = "password_only"
            self.select_key_button.configure(state="disabled")
            self.key_file_label.configure(text="نوع التشفير: كلمة مرور فقط")
        elif mode_header == MODE_PASSWORD_AND_KEY:
            self.decryption_mode = "password_and_key"
            self.select_key_button.configure(state="normal")
            self.key_file_label.configure(text="في انتظار اختيار ملف المفتاح...")
        else:
            messagebox.showerror("خطأ", "ملف مشفر غير معروف أو تالف."); self.decryption_mode = None

    def select_key_file(self):
        path = filedialog.askopenfilename(title="اختر ملف المفتاح", filetypes=[("Key Files", "*.key")])
        if path: self.key_file = path; self.key_file_label.configure(text=os.path.basename(path))

    def get_encryption_key(self, password, salt, key_file_content=None):
        base_secret = password.encode()
        if key_file_content: base_secret += key_file_content
        # --- التحصين الأمني: زيادة عدد التكرارات بشكل هائل ---
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=1_200_000)
        return base64.urlsafe_b64encode(kdf.derive(base_secret))

    def encrypt_action(self):
        if not self.source_path or not self.password_entry_enc.get():
            messagebox.showerror("خطأ", "الرجاء اختيار ملف/مجلد وإدخال كلمة مرور."); return

        self.start_processing("جاري التشفير، قد يستغرق هذا وقتًا...")
        
        password = self.password_entry_enc.get()
        use_keyfile = self.use_keyfile_check.get()
        key_file_content = None
        mode_header = MODE_PASSWORD_ONLY

        if use_keyfile:
            key_file_path = filedialog.asksaveasfilename(defaultextension=".key", filetypes=[("Key Files", "*.key")], title="احفظ ملف المفتاح في مكان آمن جدًا")
            if not key_file_path: self.stop_processing("الحالة: تم إلغاء التشفير."); return
            key_file_content = os.urandom(32)
            with open(key_file_path, 'wb') as kf: kf.write(key_file_content)
            mode_header = MODE_PASSWORD_AND_KEY
        
        is_dir = os.path.isdir(self.source_path)
        if is_dir:
            temp_zip_path = shutil.make_archive("temp_archive", 'zip', self.source_path)
            with open(temp_zip_path, 'rb') as f: data_to_encrypt = f.read()
            os.remove(temp_zip_path)
        else:
            with open(self.source_path, 'rb') as f: data_to_encrypt = f.read()

        salt = os.urandom(16)
        encryption_key = self.get_encryption_key(password, salt, key_file_content)
        fernet = Fernet(encryption_key)
        encrypted_data = fernet.encrypt(data_to_encrypt)
        
        output_path = self.source_path + ".locked"
        with open(output_path, 'wb') as f:
            f.write(mode_header); f.write(salt); f.write(encrypted_data)
        
        self.stop_processing("الحالة: جاهز")
        messagebox.showinfo("نجاح!", "✅ تم التشفير بنجاح!")
        
        if messagebox.askyesno("تأكيد الحذف", "هل تريد حذف النسخة الأصلية غير المشفرة الآن؟\n\n🚨 تحذير: هذا الإجراء لا يمكن التراجع عنه."):
            try:
                if is_dir: shutil.rmtree(self.source_path)
                else: os.remove(self.source_path)
                messagebox.showinfo("تم الحذف", "تم حذف الأصل بنجاح.")
            except Exception as e: messagebox.showerror("خطأ حذف", f"لم نتمكن من حذف الأصل: {e}")

    def decrypt_action(self):
        if not self.locked_file or not self.password_entry_dec.get():
            messagebox.showerror("خطأ", "اختر ملف وإدخل كلمة مرور."); return

        self.start_processing("جاري فك التشفير، قد يستغرق هذا وقتًا...")
        key_file_content = None
        if self.decryption_mode == "password_and_key":
            if not self.key_file: self.stop_processing("الحالة: خطأ"); messagebox.showerror("خطأ", "هذا الملف يتطلب مفتاح."); return
            with open(self.key_file, 'rb') as kf: key_file_content = kf.read()
        
        try:
            password = self.password_entry_dec.get()
            with open(self.locked_file, 'rb') as f: f.read(1); salt = f.read(16); encrypted_data = f.read()
            
            encryption_key = self.get_encryption_key(password, salt, key_file_content)
            fernet = Fernet(encryption_key)
            decrypted_data = fernet.decrypt(encrypted_data)

            output_path = self.locked_file.replace(".locked", "")
            try: # محاولة فك الضغط كـ zip
                with open("dec_temp.zip", 'wb') as f: f.write(decrypted_data)
                shutil.unpack_archive("dec_temp.zip", output_path)
                os.remove("dec_temp.zip")
            except: # إذا فشل، فهذا يعني أنه كان ملفًا واحدًا
                with open(output_path, 'wb') as f: f.write(decrypted_data)

            self.stop_processing("الحالة: جاهز")
            messagebox.showinfo("نجاح!", f"✅ تم فك التشفير بنجاح!\n\nتم حفظه في: {output_path}")

            if messagebox.askyesno("تأكيد الحذف", "هل تريد حذف الملف المشفر (.locked) الآن؟"):
                try: os.remove(self.locked_file); messagebox.showinfo("تم الحذف", "تم حذف الملف المشفر.")
                except Exception as e: messagebox.showerror("خطأ حذف", f"لم نتمكن من حذف الملف المشفر: {e}")
        except Exception as e:
            self.stop_processing("الحالة: خطأ")
            messagebox.showerror("فشل فك التشفير", "فشلت العملية. الأسباب المحتملة:\n\n- كلمة المرور غير صحيحة.\n- ملف المفتاح غير صحيح.\n- الملف تالف أو تم التلاعب به.")

if __name__ == "__main__":
    app = GodModeEncryptor()
    app.mainloop()

