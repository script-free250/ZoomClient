import os
import sys
import shutil
import base64
import customtkinter as ctk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# --- تعريفات أساسية ---
MODE_PASSWORD_ONLY = b'\x01'
MODE_PASSWORD_AND_KEY = b'\x02'
THEME_COLOR = "#00A2FF" # Electric Blue
BG_COLOR = "#1A1A1A"
FRAME_COLOR = "#242424"

# --- إعدادات المظهر ---
ctk.set_appearance_mode("Dark")

class SingularityApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Singularity")
        self.geometry("800x600")
        self.attributes('-alpha', 0.0)

        try:
            icon_path = self.resource_path("icon.ico")
            self.iconbitmap(icon_path)
        except Exception: pass

        # --- التصميم الجديد: الشريط الجانبي + المنطقة الرئيسية ---
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # الشريط الجانبي
        self.sidebar_frame = ctk.CTkFrame(self, width=200, fg_color=BG_COLOR, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsw")
        self.sidebar_frame.grid_rowconfigure(4, weight=1)
        
        logo_label = ctk.CTkLabel(self.sidebar_frame, text="Project\nSingularity", font=ctk.CTkFont(size=28, weight="bold", family="Segoe UI Black"))
        logo_label.grid(row=0, column=0, padx=20, pady=(40, 20))
        
        self.status_label = ctk.CTkLabel(self.sidebar_frame, text="الحالة: جاهز", anchor="w", text_color="gray")
        self.status_label.grid(row=5, column=0, padx=20, pady=10, sticky="sw")

        # المنطقة الرئيسية
        self.main_frame = ctk.CTkFrame(self, fg_color=FRAME_COLOR, corner_radius=0)
        self.main_frame.grid(row=0, column=1, sticky="nsew")
        self.main_frame.grid_rowconfigure(0, weight=1)
        self.main_frame.grid_columnconfigure(0, weight=1)

        self.tabview = ctk.CTkTabview(self.main_frame, fg_color=FRAME_COLOR, border_width=2, border_color=BG_COLOR)
        self.tabview.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")
        self.tabview.configure(segmented_button_selected_color=THEME_COLOR, segmented_button_selected_hover_color=THEME_COLOR, segmented_button_unselected_hover_color="#4A4A4A")
        
        self.encrypt_tab = self.tabview.add("🔒   تشفير   ")
        self.decrypt_tab = self.tabview.add("🔑   فك تشفير   ")
        
        self.setup_ui(self.encrypt_tab, "encrypt")
        self.setup_ui(self.decrypt_tab, "decrypt")
        
        self.after(200, self.fade_in)
        # متغيرات التشغيل
        self.source_path = ""
        self.locked_file = ""
        self.key_file = ""

    def setup_ui(self, tab, mode):
        tab.grid_columnconfigure(0, weight=1)
        if mode == "encrypt":
            title = ctk.CTkLabel(tab, text="تأمين ملف أو مجلد", font=ctk.CTkFont(size=22, weight="bold"))
            title.grid(row=0, column=0, padx=30, pady=20)

            path_button = ctk.CTkButton(tab, text="📂  اختر...", fg_color=THEME_COLOR, hover_color="#008ECC", command=self.select_path_to_encrypt)
            self.path_label_enc = ctk.CTkLabel(tab, text="لم يتم اختيار أي شيء", text_color="gray", anchor="w")
            password_entry = ctk.CTkEntry(tab, placeholder_text="أدخل كلمة مرور قوية جدًا", show="*", height=40)
            use_keyfile_check = ctk.CTkCheckBox(tab, text="أمان إضافي (مُوصى به): كلمة مرور + ملف مفتاح", font=ctk.CTkFont(weight="bold"), fg_color=THEME_COLOR)
            use_keyfile_check.select()
            action_button = ctk.CTkButton(tab, text="🔒  تشفير", height=50, font=ctk.CTkFont(size=20, weight="bold"), fg_color=THEME_COLOR, hover_color="#008ECC", command=self.encrypt_action)

            path_button.grid(row=1, column=0, padx=30, pady=10, sticky="w")
            self.path_label_enc.grid(row=2, column=0, padx=30, pady=5, sticky="ew")
            password_entry.grid(row=3, column=0, padx=30, pady=20, sticky="ew")
            use_keyfile_check.grid(row=4, column=0, padx=30, pady=10, sticky="w")
            action_button.grid(row=5, column=0, padx=30, pady=(30, 20), sticky="ew")

            self.password_entry_enc = password_entry
            self.use_keyfile_check = use_keyfile_check

        elif mode == "decrypt":
            title = ctk.CTkLabel(tab, text="فك تشفير ملف", font=ctk.CTkFont(size=22, weight="bold"))
            title.grid(row=0, column=0, padx=30, pady=20)
            
            select_file_button = ctk.CTkButton(tab, text="📂  اختر الملف المشفر...", fg_color=THEME_COLOR, hover_color="#008ECC", command=self.select_file_to_decrypt)
            self.locked_file_label = ctk.CTkLabel(tab, text="...", text_color="gray")
            
            select_key_button = ctk.CTkButton(tab, text="🔑  اختر ملف المفتاح...", fg_color=THEME_COLOR, hover_color="#008ECC", command=self.select_key_file)
            self.key_file_label = ctk.CTkLabel(tab, text="...", text_color="gray")
            
            password_entry = ctk.CTkEntry(tab, placeholder_text="أدخل كلمة المرور", show="*", height=40)
            action_button = ctk.CTkButton(tab, text="🔑  فك التشفير", height=50, font=ctk.CTkFont(size=20, weight="bold"), fg_color=THEME_COLOR, hover_color="#008ECC", command=self.decrypt_action)

            select_file_button.grid(row=1, column=0, padx=30, pady=(10, 5), sticky="ew")
            self.locked_file_label.grid(row=2, column=0, padx=30, pady=(0, 15), sticky="w")
            select_key_button.grid(row=3, column=0, padx=30, pady=(10, 5), sticky="ew")
            self.key_file_label.grid(row=4, column=0, padx=30, pady=(0, 15), sticky="w")
            password_entry.grid(row=5, column=0, padx=30, pady=15, sticky="ew")
            action_button.grid(row=6, column=0, padx=30, pady=(20, 15), sticky="ew")
            
            self.password_entry_dec = password_entry
            self.select_key_button_dec = select_key_button

    # --- باقي الدوال المنطقية (مع التحديثات) ---
    def resource_path(self, relative_path):
        try: base_path = sys._MEIPASS
        except Exception: base_path = os.path.abspath(".")
        return os.path.join(base_path, relative_path)
    def fade_in(self):
        alpha = self.attributes('-alpha')
        if alpha < 1: alpha += 0.08; self.attributes('-alpha', alpha); self.after(15, self.fade_in)
    def update_status(self, text): self.status_label.configure(text=text); self.update_idletasks()
    def select_path_to_encrypt(self):
        path = filedialog.askdirectory(title="اختر مجلدًا")
        if not path: path = filedialog.askopenfilename(title="أو اختر ملفًا واحدًا")
        if path: self.source_path = path; self.path_label_enc.configure(text=os.path.basename(path))
    def select_file_to_decrypt(self):
        path = filedialog.askopenfilename(title="اختر الملف المشفر", filetypes=[("Singularity Locked", "*.locked")])
        if not path: return
        self.locked_file = path; self.locked_file_label.configure(text=os.path.basename(path))
        with open(path, 'rb') as f: mode_header = f.read(1)
        if mode_header == MODE_PASSWORD_ONLY:
            self.select_key_button_dec.configure(state="disabled", text="لا يتطلب مفتاح")
            self.key_file_label.configure(text="")
        elif mode_header == MODE_PASSWORD_AND_KEY:
            self.select_key_button_dec.configure(state="normal", text="🔑  اختر ملف المفتاح...")
            self.key_file_label.configure(text="في انتظار اختيار ملف المفتاح...")
    def select_key_file(self):
        path = filedialog.askopenfilename(title="اختر ملف المفتاح", filetypes=[("Key Files", "*.key")])
        if path: self.key_file = path; self.key_file_label.configure(text=os.path.basename(path))
    def get_encryption_key(self, password, salt, key_file_content=None):
        base_secret = password.encode()
        if key_file_content: base_secret += key_file_content
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=1_200_000)
        return base64.urlsafe_b64encode(kdf.derive(base_secret))
    def encrypt_action(self):
        if not self.source_path or not self.password_entry_enc.get(): messagebox.showerror("خطأ", "الرجاء اختيار ملف/مجلد وإدخال كلمة مرور."); return
        password = self.password_entry_enc.get(); use_keyfile = self.use_keyfile_check.get(); key_file_content = None; mode_header = MODE_PASSWORD_ONLY
        if use_keyfile:
            key_file_path = filedialog.asksaveasfilename(defaultextension=".key", filetypes=[("Key Files", "*.key")], title="احفظ ملف المفتاح في مكان آمن جدًا")
            if not key_file_path: self.update_status("الحالة: تم إلغاء التشفير."); return
            key_file_content = os.urandom(32); 
            with open(key_file_path, 'wb') as kf: kf.write(key_file_content)
            mode_header = MODE_PASSWORD_AND_KEY
        self.update_status("الحالة: جاري ضغط الملفات..."); is_dir = os.path.isdir(self.source_path)
        if is_dir:
            temp_zip_path = shutil.make_archive("temp_archive", 'zip', self.source_path)
            with open(temp_zip_path, 'rb') as f: data_to_encrypt = f.read(); os.remove(temp_zip_path)
        else:
            with open(self.source_path, 'rb') as f: data_to_encrypt = f.read()
        self.update_status("الحالة: جاري التشفير (قد يطول)..."); salt = os.urandom(16); encryption_key = self.get_encryption_key(password, salt, key_file_content); fernet = Fernet(encryption_key); encrypted_data = fernet.encrypt(data_to_encrypt)
        self.update_status("الحالة: جاري كتابة الملف..."); output_path = self.source_path + ".locked"
        with open(output_path, 'wb') as f: f.write(mode_header); f.write(salt); f.write(encrypted_data)
        self.update_status("الحالة: جاهز."); messagebox.showinfo("نجاح!", "✅ تم التشفير بنجاح!")
        if messagebox.askyesno("تأكيد", "هل تريد حذف النسخة الأصلية الآن؟"):
            try:
                if is_dir: shutil.rmtree(self.source_path)
                else: os.remove(self.source_path)
            except Exception as e: messagebox.showerror("خطأ", f"لم نتمكن من حذف الأصل: {e}")
    def decrypt_action(self):
        if not self.locked_file or not self.password_entry_dec.get(): messagebox.showerror("خطأ", "اختر ملف وأدخل كلمة مرور."); return
        self.update_status("الحالة: جاري فك التشفير (قد يطول)...")
        try:
            password = self.password_entry_dec.get(); key_file_content = None
            if self.select_key_button_dec.cget("state") == "normal":
                if not self.key_file: self.update_status("الحالة: خطأ."); messagebox.showerror("خطأ", "هذا الملف يتطلب مفتاح."); return
                with open(self.key_file, 'rb') as kf: key_file_content = kf.read()
            with open(self.locked_file, 'rb') as f: f.read(1); salt = f.read(16); encrypted_data = f.read()
            encryption_key = self.get_encryption_key(password, salt, key_file_content); fernet = Fernet(encryption_key); decrypted_data = fernet.decrypt(encrypted_data)
            self.update_status("الحالة: جاهز.")
            output_folder = filedialog.askdirectory(title="اختر مجلدًا لحفظ الملفات المفكوكة فيه")
            if not output_folder: self.update_status("الحالة: تم إلغاء الحفظ."); return
            # --- هذا هو الحل لمشكلة عدم ظهور الملف ---
            # تحديد المسار النهائي للمجلد أو الملف
            final_output_path = os.path.join(output_folder, os.path.basename(self.locked_file).replace(".locked", ""))
            try: # محاولة فك الضغط كمجلد
                with open("dec_temp.zip", 'wb') as f: f.write(decrypted_data)
                os.makedirs(final_output_path, exist_ok=True) # إنشاء المجلد الوجهة
                shutil.unpack_archive("dec_temp.zip", final_output_path)
                os.remove("dec_temp.zip")
            except: # إذا فشل، فهذا يعني أنه كان ملفًا واحدًا
                with open(final_output_path, 'wb') as f: f.write(decrypted_data)
            messagebox.showinfo("نجاح!", f"✅ تم فك التشفير بنجاح!\n\nتم الحفظ في: {final_output_path}")
            if messagebox.askyesno("تأكيد", "هل تريد حذف الملف المشفر الآن؟"):
                try: os.remove(self.locked_file)
                except Exception as e: messagebox.showerror("خطأ", f"لم نتمكن من حذف الملف المشفر: {e}")
        except Exception: self.update_status("الحالة: خطأ."); messagebox.showerror("فشل", "فشلت العملية. تأكد من صحة كلمة المرور أو ملف المفتاح.")

if __name__ == "__main__":
    app = SingularityApp()
    app.mainloop()
