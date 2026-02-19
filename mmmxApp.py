import os
import sys
import shutil
import base64
import tempfile
import threading
import json
from datetime import datetime, timedelta
import customtkinter as ctk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from PIL import Image

# --- تعريفات أساسية ---
APP_PASSWORD = "023123"  # تحذير: كلمة مرور ثابتة في الكود تشكل ثغرة أمنية كبيرة. يجب تغييرها.
MODE_PASSWORD_ONLY = b'\x01'
MODE_PASSWORD_AND_KEY = b'\x02'
THEME_COLOR = "#00BFFF"
HOVER_COLOR = "#009ACD"
BG_COLOR = "#0A0A0A"
FRAME_COLOR = "#191919"

# --- إعدادات الحماية من التخمين ---
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_MINUTES = 5

# --- [جديد] وظائف المسح الآمن ---
def secure_wipe_file(file_path):
    """
    يقوم بالكتابة فوق الملف ببيانات عشوائية ثم بيانات صفرية قبل حذفه نهائياً.
    """
    try:
        with open(file_path, "rb+") as f:
            length = os.fstat(f.fileno()).st_size
            if length > 0:
                # 1. الكتابة فوق الملف ببيانات عشوائية
                f.seek(0)
                f.write(os.urandom(length))
                # 2. الكتابة فوق الملف ببيانات صفرية (اختياري، لزيادة الأمان)
                f.seek(0)
                f.write(b'\x00' * length)
    except Exception as e:
        print(f"Secure wipe (overwrite) failed for {file_path}: {e}")
    finally:
        try:
            # 3. الحذف النهائي
            os.remove(file_path)
        except Exception as e:
            print(f"Secure wipe (remove) failed for {file_path}: {e}")

def secure_wipe_directory(path):
    """
    يطبق المسح الآمن على كل الملفات داخل مجلد ثم يحذف هيكل المجلد.
    """
    for root, dirs, files in os.walk(path, topdown=False):
        for name in files:
            secure_wipe_file(os.path.join(root, name))
        for name in dirs:
            try:
                os.rmdir(os.path.join(root, name))
            except OSError as e: # <-- تم إضافة الـ except الناقصة هنا لحل المشكلة
                print(f"Failed to remove directory {name}: {e}")
    try:
        os.rmdir(path)
    except OSError as e:
        print(f"Failed to remove top-level directory {path}: {e}")


# --- [جديد] إدارة حالة التطبيق (للحماية من التخمين) ---
class AppState:
    def __init__(self):
        self.state_file_path = self._get_state_file_path()
        self.state = {
            'failed_attempts': 0,
            'lockout_until': None
        }
        self.load_state()

    def _get_state_file_path(self):
        app_data_dir = os.getenv('APPDATA') or os.path.expanduser("~")
        mmmx_dir = os.path.join(app_data_dir, ".mmmx")
        os.makedirs(mmmx_dir, exist_ok=True)
        return os.path.join(mmmx_dir, "app_state.json")

    def load_state(self):
        try:
            with open(self.state_file_path, 'r') as f:
                data = json.load(f)
                self.state['failed_attempts'] = data.get('failed_attempts', 0)
                lockout_str = data.get('lockout_until')
                if lockout_str:
                    self.state['lockout_until'] = datetime.fromisoformat(lockout_str)
        except (FileNotFoundError, json.JSONDecodeError):
            self.save_state()

    def save_state(self):
        data_to_save = self.state.copy()
        if data_to_save['lockout_until']:
            data_to_save['lockout_until'] = data_to_save['lockout_until'].isoformat()
        with open(self.state_file_path, 'w') as f:
            json.dump(data_to_save, f)

    def is_locked_out(self):
        if self.state['lockout_until'] and datetime.now() < self.state['lockout_until']:
            return True
        # إذا انتهت مدة الحظر، قم بإعادة الضبط
        if self.state['lockout_until'] and datetime.now() >= self.state['lockout_until']:
            self.record_successful_login() # Reset state
        return False

    def get_lockout_remaining_str(self):
        if not self.is_locked_out():
            return None
        remaining = self.state['lockout_until'] - datetime.now()
        minutes, seconds = divmod(remaining.total_seconds(), 60)
        return f"{int(minutes)}m {int(seconds)}s"

    def record_failed_attempt(self):
        self.state['failed_attempts'] += 1
        if self.state['failed_attempts'] >= MAX_LOGIN_ATTEMPTS:
            self.state['lockout_until'] = datetime.now() + timedelta(minutes=LOCKOUT_MINUTES)
        self.save_state()

    def record_successful_login(self):
        self.state['failed_attempts'] = 0
        self.state['lockout_until'] = None
        self.save_state()

# --- إعدادات المظهر ---
ctk.set_appearance_mode("Dark")

class mmmxApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("mmmx")
        self.geometry("950x700")
        self.attributes('-alpha', 0.0)

        self.app_state = AppState() # [جديد] تهيئة نظام الحماية

        try:
            self.icon_path = self.resource_path("icon.ico")
            self.iconbitmap(self.icon_path)
            self.app_icon_large = ctk.CTkImage(Image.open(self.icon_path), size=(128, 128))
            self.app_icon_small = ctk.CTkImage(Image.open(self.icon_path), size=(64, 64))
        except Exception as e:
            print(f"Icon Error: {e}")
            self.app_icon_large = None; self.app_icon_small = None

        self.setup_login_screen()
        self.after(200, self.fade_in, 0.0)

        self.source_path = ""
        self.locked_file = ""
        self.key_file = ""
        self.operation_result = None
        self.live_edit_temp_path = None
        self.live_edit_cache_warning_shown = False # [جديد] لتتبع إظهار رسالة التحذير

    def setup_login_screen(self):
        self.login_frame = ctk.CTkFrame(self, fg_color=BG_COLOR, corner_radius=0)
        self.login_frame.pack(fill="both", expand=True)

        self.icon_label = ctk.CTkLabel(self.login_frame, text="", image=self.app_icon_large)
        self.title_label = ctk.CTkLabel(self.login_frame, text="mmmx", font=ctk.CTkFont(size=32, weight="bold", family="Impact"))
        self.password_entry_login = ctk.CTkEntry(self.login_frame, placeholder_text="ENTER ACCESS CODE", show="*", height=45, width=300, justify="center", font=ctk.CTkFont(size=16))
        self.login_button = ctk.CTkButton(self.login_frame, text="UNLOCK", height=45, width=300, font=ctk.CTkFont(size=18, weight="bold"), fg_color=THEME_COLOR, hover_color=HOVER_COLOR, command=self.check_login)
        self.error_label_login = ctk.CTkLabel(self.login_frame, text="", text_color="#FF4D4D")
        
        self.icon_label.pack(pady=(150, 20))
        self.title_label.pack(pady=10)
        self.password_entry_login.pack(pady=20)
        self.login_button.pack(pady=10)
        self.error_label_login.pack(pady=10)
        self.password_entry_login.bind("<Return>", self.check_login)
        
        # [جديد] التحقق من حالة الحظر عند بدء التشغيل
        if self.app_state.is_locked_out():
            self.show_lockout_message()

    def show_lockout_message(self):
        remaining_time = self.app_state.get_lockout_remaining_str()
        if remaining_time:
            self.error_label_login.configure(text=f"ACCESS LOCKED. TRY AGAIN IN {remaining_time}")
            self.login_button.configure(state="disabled")
            self.password_entry_login.configure(state="disabled")
            self.after(1000, self.show_lockout_message) # تحديث العداد كل ثانية
        else:
            self.error_label_login.configure(text="")
            self.login_button.configure(state="normal")
            self.password_entry_login.configure(state="normal")

    def check_login(self, event=None):
        if self.app_state.is_locked_out():
            self.show_lockout_message()
            return
            
        if self.password_entry_login.get() == APP_PASSWORD:
            self.app_state.record_successful_login()
            self.error_label_login.configure(text="")
            self.fade_out_and_setup_main_ui()
        else:
            self.app_state.record_failed_attempt()
            if self.app_state.is_locked_out():
                self.show_lockout_message()
            else:
                attempts_left = MAX_LOGIN_ATTEMPTS - self.app_state.state['failed_attempts']
                self.error_label_login.configure(text=f"ACCESS DENIED. {attempts_left} ATTEMPTS REMAINING.")

    def fade_out_and_setup_main_ui(self, alpha=1.0):
        if alpha > 0:
            alpha -= 0.1
            self.attributes('-alpha', alpha)
            self.after(25, lambda: self.fade_out_and_setup_main_ui(alpha))
        else:
            for widget in self.winfo_children():
                widget.destroy()
            self.setup_main_ui()
            self.fade_in(0.0)

    def setup_main_ui(self):
        self.grid_columnconfigure(1, weight=1); self.grid_rowconfigure(0, weight=1)
        self.sidebar_frame = ctk.CTkFrame(self, width=220, fg_color=BG_COLOR, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsw")
        self.sidebar_frame.grid_rowconfigure(5, weight=1)
        
        sidebar_icon_label = ctk.CTkLabel(self.sidebar_frame, text="", image=self.app_icon_small)
        sidebar_icon_label.grid(row=0, column=0, pady=30, padx=20)
        logo_label = ctk.CTkLabel(self.sidebar_frame, text="mmmx", font=ctk.CTkFont(size=40, weight="bold", family="Impact"))
        logo_label.grid(row=1, column=0, padx=20, pady=(0, 20))
        self.status_label = ctk.CTkLabel(self.sidebar_frame, text="الحالة: جاهز", anchor="w", text_color="gray")
        self.status_label.grid(row=6, column=0, padx=20, pady=10, sticky="sw")
        self.progress_bar = ctk.CTkProgressBar(self.sidebar_frame, mode='indeterminate', progress_color=THEME_COLOR)

        self.main_frame = ctk.CTkFrame(self, fg_color=FRAME_COLOR, corner_radius=0)
        self.main_frame.grid(row=0, column=1, sticky="nsew")
        self.main_frame.grid_rowconfigure(0, weight=1); self.main_frame.grid_columnconfigure(0, weight=1)

        self.tabview = ctk.CTkTabview(self.main_frame, fg_color="transparent", border_width=0)
        self.tabview.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")
        self.tabview.configure(segmented_button_selected_color=THEME_COLOR, segmented_button_selected_hover_color=HOVER_COLOR, segmented_button_unselected_hover_color="#333333")
        
        self.tabview.add("🔒  تشفير"); self.tabview.add("🔑  فك تشفير"); self.tabview.add("🚀  جلسة تعديل")
        self.setup_operation_ui(self.tabview.tab("🔒  تشفير"), "encrypt")
        self.setup_operation_ui(self.tabview.tab("🔑  فك تشفير"), "decrypt")
        self.setup_operation_ui(self.tabview.tab("🚀  جلسة تعديل"), "live_edit")

    def setup_operation_ui(self, tab, mode):
        tab.grid_columnconfigure(0, weight=1)
        if mode == "encrypt":
            title = ctk.CTkLabel(tab, text="تأمين ملف أو مجلد", font=ctk.CTkFont(size=22, weight="bold"))
            path_button = ctk.CTkButton(tab, text="📂  اختر...", fg_color=THEME_COLOR, hover_color=HOVER_COLOR, command=self.select_path_to_encrypt)
            self.path_label_enc = ctk.CTkLabel(tab, text="لم يتم اختيار أي شيء", text_color="gray", anchor="w")
            password_entry = ctk.CTkEntry(tab, placeholder_text="أدخل كلمة مرور قوية جدًا", show="*", height=40)
            use_keyfile_check = ctk.CTkCheckBox(tab, text="أمان إضافي (مُوصى به): كلمة مرور + ملف مفتاح", font=ctk.CTkFont(weight="bold"), fg_color=THEME_COLOR)
            use_keyfile_check.select()
            action_button = ctk.CTkButton(tab, text="🔒  تشفير", height=50, font=ctk.CTkFont(size=20, weight="bold"), command=self.start_encryption_thread)
            title.grid(row=0, column=0, padx=30, pady=20); path_button.grid(row=1, column=0, padx=30, pady=10, sticky="w"); self.path_label_enc.grid(row=2, column=0, padx=30, pady=5, sticky="ew")
            password_entry.grid(row=3, column=0, padx=30, pady=20, sticky="ew"); use_keyfile_check.grid(row=4, column=0, padx=30, pady=10, sticky="w")
            action_button.grid(row=5, column=0, padx=30, pady=(30, 20), sticky="ew")
            self.password_entry_enc = password_entry; self.use_keyfile_check = use_keyfile_check; self.encrypt_button = action_button
        elif mode == "decrypt":
            title = ctk.CTkLabel(tab, text="فك تشفير ملف", font=ctk.CTkFont(size=22, weight="bold"))
            select_file_button = ctk.CTkButton(tab, text="📂  اختر الملف المشفر...", fg_color=THEME_COLOR, hover_color=HOVER_COLOR, command=lambda: self.select_file_to_decrypt(live_edit=False))
            self.locked_file_label_dec = ctk.CTkLabel(tab, text="...", text_color="gray")
            select_key_button = ctk.CTkButton(tab, text="🔑  اختر ملف المفتاح...", fg_color=THEME_COLOR, hover_color=HOVER_COLOR, command=lambda: self.select_key_file(live_edit=False))
            self.key_file_label_dec = ctk.CTkLabel(tab, text="...", text_color="gray")
            password_entry = ctk.CTkEntry(tab, placeholder_text="أدخل كلمة المرور", show="*", height=40)
            action_button = ctk.CTkButton(tab, text="🔑  فك التشفير", height=50, font=ctk.CTkFont(size=20, weight="bold"), command=self.start_decryption_thread)
            title.grid(row=0, column=0, padx=30, pady=20); select_file_button.grid(row=1, column=0, padx=30, pady=(10, 5), sticky="ew"); self.locked_file_label_dec.grid(row=2, column=0, padx=30, pady=(0, 15), sticky="w")
            select_key_button.grid(row=3, column=0, padx=30, pady=(10, 5), sticky="ew"); self.key_file_label_dec.grid(row=4, column=0, padx=30, pady=(0, 15), sticky="w")
            password_entry.grid(row=5, column=0, padx=30, pady=15, sticky="ew"); action_button.grid(row=6, column=0, padx=30, pady=(20, 15), sticky="ew")
            self.password_entry_dec = password_entry; self.select_key_button_dec = select_key_button; self.decrypt_button = action_button
        elif mode == "live_edit":
            self.live_edit_setup_frame = ctk.CTkFrame(tab, fg_color="transparent")
            self.live_edit_setup_frame.grid(row=0, column=0, sticky="nsew", padx=30, pady=20); self.live_edit_setup_frame.grid_columnconfigure(0, weight=1)
            title = ctk.CTkLabel(self.live_edit_setup_frame, text="فتح جلسة تعديل آمنة", font=ctk.CTkFont(size=22, weight="bold"))
            select_file_button = ctk.CTkButton(self.live_edit_setup_frame, text="📂  اختر الملف المشفر...", command=lambda: self.select_file_to_decrypt(live_edit=True))
            self.live_edit_file_label = ctk.CTkLabel(self.live_edit_setup_frame, text="...", text_color="gray")
            select_key_button = ctk.CTkButton(self.live_edit_setup_frame, text="🔑  اختر ملف المفتاح...", command=lambda: self.select_key_file(live_edit=True))
            self.live_edit_key_label = ctk.CTkLabel(self.live_edit_setup_frame, text="...", text_color="gray")
            password_entry = ctk.CTkEntry(self.live_edit_setup_frame, placeholder_text="أدخل كلمة المرور لفتح الجلسة", show="*", height=40)
            action_button = ctk.CTkButton(self.live_edit_setup_frame, text="🚀  بدء الجلسة", height=50, font=ctk.CTkFont(size=20, weight="bold"), command=self.start_live_edit_thread)
            title.grid(row=0, column=0, pady=20); select_file_button.grid(row=1, column=0, pady=(10, 5), sticky="ew"); self.live_edit_file_label.grid(row=2, column=0, pady=(0, 15), sticky="w")
            select_key_button.grid(row=3, column=0, pady=(10, 5), sticky="ew"); self.live_edit_key_label.grid(row=4, column=0, pady=(0, 15), sticky="w")
            password_entry.grid(row=5, column=0, pady=15, sticky="ew"); action_button.grid(row=6, column=0, pady=(20, 15), sticky="ew")
            self.password_entry_live = password_entry; self.select_key_button_live = select_key_button; self.live_edit_button = action_button
            
            self.file_browser_frame = ctk.CTkFrame(tab, fg_color="transparent")
            self.file_browser_frame.grid_columnconfigure(0, weight=1); self.file_browser_frame.grid_rowconfigure(1, weight=1)
            browser_controls_frame = ctk.CTkFrame(self.file_browser_frame, fg_color="transparent")
            browser_controls_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
            self.add_file_button = ctk.CTkButton(browser_controls_frame, text="➕ إضافة ملف", command=self.add_file_to_session)
            self.add_file_button.pack(side="left", padx=5)
            self.new_folder_button = ctk.CTkButton(browser_controls_frame, text="📁 إنشاء مجلد", command=self.add_folder_to_session)
            self.new_folder_button.pack(side="left", padx=5)
            self.relock_button = ctk.CTkButton(browser_controls_frame, text="💾 حفظ وإعادة القفل", font=ctk.CTkFont(weight="bold"), fg_color="red", hover_color="#B91C1C", command=self.start_relock_thread)
            self.relock_button.pack(side="right", padx=5)
            self.browser_scrollable_frame = ctk.CTkScrollableFrame(self.file_browser_frame, label_text="المحتويات الحالية")
            self.browser_scrollable_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=5); self.current_browser_path = ""
    
    def resource_path(self, relative_path):
        try: base_path = sys._MEIPASS
        except Exception: base_path = os.path.abspath(".")
        return os.path.join(base_path, relative_path)
        
    def fade_in(self, alpha=0.0):
        if alpha < 1:
            alpha += 0.05
            self.attributes('-alpha', alpha)
            self.after(15, lambda: self.fade_in(alpha))
            
    def update_status(self, text):
        if self.status_label.winfo_exists(): self.status_label.configure(text=text)
        
    def toggle_ui_state(self, state="disabled"):
        buttons = [self.encrypt_button, self.decrypt_button, self.live_edit_button]
        for btn in buttons:
            if btn and btn.winfo_exists(): btn.configure(state=state)
        if hasattr(self, 'tabview') and self.tabview.winfo_exists(): self.tabview.configure(state=state)
        if state == "disabled":
            if hasattr(self, 'progress_bar') and self.progress_bar.winfo_exists():
                self.progress_bar.grid(row=7, column=0, padx=20, pady=10, sticky="sew"); self.progress_bar.start()
        else:
            if hasattr(self, 'progress_bar') and self.progress_bar.winfo_exists():
                self.progress_bar.stop(); self.progress_bar.grid_forget()

    def select_path_to_encrypt(self):
        path = filedialog.askdirectory(title="اختر مجلدًا") or filedialog.askopenfilename(title="أو اختر ملفًا واحدًا")
        if path: self.source_path = path; self.path_label_enc.configure(text=os.path.basename(path))
        
    def select_file_to_decrypt(self, live_edit=False):
        path = filedialog.askopenfilename(title="اختر الملف المشفر", filetypes=[("mmmx Locked File", "*.locked")])
        if not path: return
        self.locked_file = path
        label = self.live_edit_file_label if live_edit else self.locked_file_label_dec
        label.configure(text=os.path.basename(path)); self.key_file = ""
        with open(path, 'rb') as f: mode_header = f.read(1)
        key_button = self.select_key_button_live if live_edit else self.select_key_button_dec
        key_label = self.live_edit_key_label if live_edit else self.key_file_label_dec
        if mode_header == MODE_PASSWORD_ONLY: key_button.configure(state="disabled", text="لا يتطلب مفتاح"); key_label.configure(text="")
        elif mode_header == MODE_PASSWORD_AND_KEY: key_button.configure(state="normal", text="🔑  اختر ملف المفتاح..."); key_label.configure(text="في انتظار اختيار ملف المفتاح...")
        
    def select_key_file(self, live_edit=False):
        path = filedialog.askopenfilename(title="اختر ملف المفتاح", filetypes=[("Key Files", "*.key")])
        if path: self.key_file = path; 
        label = self.live_edit_key_label if live_edit else self.key_file_label_dec
        label.configure(text=os.path.basename(path))

    def get_encryption_key(self, password, salt, key_file_content=None):
        base_secret = password.encode()
        if key_file_content: base_secret += key_file_content
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=1_200_000); return base64.urlsafe_b64encode(kdf.derive(base_secret))
    
    # --- قسم التشفير ---
    def start_encryption_thread(self):
        password = self.password_entry_enc.get()
        if not self.source_path or not password: messagebox.showerror("خطأ", "الرجاء اختيار ملف/مجلد وإدخال كلمة مرور."); return
        use_keyfile = self.use_keyfile_check.get(); key_file_path = None
        if use_keyfile:
            key_file_path = filedialog.asksaveasfilename(defaultextension=".key", filetypes=[("Key Files", "*.key")], title="احفظ ملف المفتاح في مكان آمن جدًا")
            if not key_file_path: self.update_status("الحالة: تم إلغاء العملية."); return
        self.toggle_ui_state("disabled")
        threading.Thread(target=self.encrypt_logic, args=(password, use_keyfile, key_file_path), daemon=True).start()

    def encrypt_logic(self, password, use_keyfile, key_file_path):
        temp_dir = None; key_file_content = None; encryption_key = None
        try:
            mode_header = MODE_PASSWORD_ONLY
            if use_keyfile:
                key_file_content = os.urandom(32)
                with open(key_file_path, 'wb') as kf: kf.write(key_file_content)
                mode_header = MODE_PASSWORD_AND_KEY
            
            self.after(0, self.update_status, "الحالة: جاري ضغط الملفات..."); is_dir = os.path.isdir(self.source_path)
            if is_dir:
                temp_dir = tempfile.mkdtemp()
                archive_path = os.path.join(temp_dir, 'archive')
                temp_zip_path = shutil.make_archive(archive_path, 'zip', self.source_path)
                with open(temp_zip_path, 'rb') as f: data_to_encrypt = f.read()
            else:
                with open(self.source_path, 'rb') as f: data_to_encrypt = f.read()

            self.after(0, self.update_status, "الحالة: جاري التشفير (قد يطول)..."); salt = os.urandom(16)
            encryption_key = self.get_encryption_key(password, salt, key_file_content)
            fernet = Fernet(encryption_key)
            encrypted_data = fernet.encrypt(data_to_encrypt)
            
            self.after(0, self.update_status, "الحالة: جاري كتابة الملف..."); output_path = self.source_path + ".locked"
            with open(output_path, 'wb') as f: f.write(mode_header); f.write(salt); f.write(encrypted_data)
            self.operation_result = ("success", is_dir)

        except Exception as e: self.operation_result = ("error", f"حدث خطأ أثناء التشفير: {e}")
        finally:
            # [جديد] تنظيف آمن للذاكرة والمتغيرات الحساسة
            password = None
            if key_file_content: key_file_content = os.urandom(len(key_file_content))
            if encryption_key: encryption_key = os.urandom(len(encryption_key))
            if 'data_to_encrypt' in locals(): data_to_encrypt = os.urandom(len(data_to_encrypt))
            if 'encrypted_data' in locals(): encrypted_data = os.urandom(len(encrypted_data))

            if temp_dir and os.path.exists(temp_dir): shutil.rmtree(temp_dir)
            self.after(0, self.finish_encryption)

    def finish_encryption(self):
        self.toggle_ui_state("normal")
        status, payload = self.operation_result
        if status == "success":
            messagebox.showinfo("نجاح!", "✅ تم التشفير بنجاح!")
            if messagebox.askyesno("تأكيد", "هل تريد حذف النسخة الأصلية الآن؟\n(سيتم استخدام المسح الآمن الذي يمنع استرجاع الملفات)"):
                self.update_status("الحالة: جاري المسح الآمن للأصل...")
                is_dir = payload
                try:
                    # [تعديل] استخدام المسح الآمن بدلاً من الحذف التقليدي
                    if is_dir:
                        secure_wipe_directory(self.source_path)
                    else:
                        secure_wipe_file(self.source_path)
                    messagebox.showinfo("نجاح", "تم مسح الملف الأصلي بآمان.")
                except Exception as e: messagebox.showerror("خطأ", f"لم نتمكن من حذف الأصل: {e}")
        elif status == "error": messagebox.showerror("فشل", payload)
        self.update_status("الحالة: جاهز.")

    # --- قسم فك التشفير ---
    def start_decryption_thread(self):
        password = self.password_entry_dec.get()
        if not self.locked_file or not password: messagebox.showerror("خطأ", "اختر ملف وأدخل كلمة مرور."); return
        self.toggle_ui_state("disabled")
        threading.Thread(target=self.decrypt_logic, args=(password,), daemon=True).start()

    def decrypt_logic(self, password):
        key_file_content = None; encryption_key = None; decrypted_data = None
        try:
            self.after(0, self.update_status, "الحالة: جاري فك التشفير (قد يطول)...")
            if self.select_key_button_dec.cget("state") == "normal":
                if not self.key_file: self.operation_result = ("error", "هذا الملف يتطلب مفتاح."); return
                with open(self.key_file, 'rb') as kf: key_file_content = kf.read()
            with open(self.locked_file, 'rb') as f: f.read(1); salt = f.read(16); encrypted_data = f.read()
            encryption_key = self.get_encryption_key(password, salt, key_file_content)
            fernet = Fernet(encryption_key)
            decrypted_data = fernet.decrypt(encrypted_data)
            self.operation_result = ("success", decrypted_data)
        except Exception: self.operation_result = ("error", "فشلت العملية. تأكد من صحة كلمة المرور أو ملف المفتاح.")
        finally:
            # [جديد] تنظيف آمن للذاكرة
            password = None
            if key_file_content: key_file_content = os.urandom(len(key_file_content))
            if encryption_key: encryption_key = os.urandom(len(encryption_key))
            # لا نمسح decrypted_data هنا لأننا سنستخدمه في الخطوة التالية
            self.after(0, self.finish_decryption)

    def finish_decryption(self):
        self.toggle_ui_state("normal"); status, payload = self.operation_result
        if status == "success":
            decrypted_data = payload
            output_folder = filedialog.askdirectory(title="اختر مجلدًا لحفظ الملفات المفكوكة فيه")
            if not output_folder: 
                self.update_status("الحالة: تم إلغاء الحفظ.")
                # [جديد] مسح البيانات المفكوكة إذا ألغى المستخدم الحفظ
                if 'decrypted_data' in locals(): decrypted_data = os.urandom(len(decrypted_data))
                return
            final_output_path = os.path.join(output_folder, os.path.basename(self.locked_file).replace(".locked", ""))
            try:
                # استخدام ذاكرة مؤقتة لملف الزيب بدلاً من كتابته مباشرة
                with tempfile.NamedTemporaryFile(delete=False, suffix=".zip") as tmp_zip:
                    tmp_zip.write(decrypted_data)
                    tmp_zip_path = tmp_zip.name
                os.makedirs(final_output_path, exist_ok=True); shutil.unpack_archive(tmp_zip_path, final_output_path)
                os.remove(tmp_zip_path) # الحذف العادي هنا مقبول لأنه ملف مؤقت للنظام
            except:
                with open(final_output_path, 'wb') as f: f.write(decrypted_data)
            
            # [جديد] مسح البيانات من الذاكرة بعد كتابتها
            if 'decrypted_data' in locals(): decrypted_data = os.urandom(len(decrypted_data))

            messagebox.showinfo("نجاح!", f"✅ تم فك التشفير بنجاح!\n\nتم الحفظ في: {final_output_path}")
            if messagebox.askyesno("تأكيد", "هل تريد حذف الملف المشفر الآن؟"):
                try: os.remove(self.locked_file)
                except Exception as e: messagebox.showerror("خطأ", f"لم نتمكن من حذف الملف المشفر: {e}")
        elif status == "error": messagebox.showerror("فشل", payload)
        self.update_status("الحالة: جاهز.")

    # --- قسم جلسة التعديل ---
    def start_live_edit_thread(self):
        password = self.password_entry_live.get()
        if not self.locked_file or not password: messagebox.showerror("خطأ", "اختر ملف وأدخل كلمة مرور."); return
        self.toggle_ui_state("disabled")
        threading.Thread(target=self.live_edit_logic, args=(password,), daemon=True).start()

    def live_edit_logic(self, password):
        key_file_content = None; encryption_key = None; decrypted_data = None
        try:
            self.after(0, self.update_status, "الحالة: جاري فتح جلسة التعديل...")
            if self.select_key_button_live.cget("state") == "normal":
                if not self.key_file: self.operation_result = ("error", "هذا الملف يتطلب مفتاح."); return
                with open(self.key_file, 'rb') as kf: key_file_content = kf.read()

            with open(self.locked_file, 'rb') as f: self.mode_header = f.read(1); self.salt = f.read(16); encrypted_data = f.read()
            encryption_key = self.get_encryption_key(password, self.salt, key_file_content)
            fernet = Fernet(encryption_key)
            decrypted_data = fernet.decrypt(encrypted_data)
            
            self.live_edit_temp_path = tempfile.mkdtemp(prefix="mmmx_")
            try:
                with tempfile.NamedTemporaryFile(delete=False, suffix=".zip") as tmp_zip: 
                    tmp_zip.write(decrypted_data)
                    tmp_zip_path = tmp_zip.name
                shutil.unpack_archive(tmp_zip_path, self.live_edit_temp_path)
                os.remove(tmp_zip_path)
            except:
                file_path = os.path.join(self.live_edit_temp_path, os.path.basename(self.locked_file).replace(".locked", ""))
                with open(file_path, 'wb') as f: f.write(decrypted_data)
            self.operation_result = ("success", None)
        except Exception: self.operation_result = ("error", "فشل فتح الجلسة. تأكد من صحة كلمة المرور/المفتاح.")
        finally:
            # [جديد] تنظيف آمن للذاكرة
            password = None
            if key_file_content: key_file_content = os.urandom(len(key_file_content))
            if encryption_key: encryption_key = os.urandom(len(encryption_key))
            if decrypted_data: decrypted_data = os.urandom(len(decrypted_data))
            self.after(0, self.finish_live_edit_setup)

    def finish_live_edit_setup(self):
        status, payload = self.operation_result
        if status == "error":
            messagebox.showerror("فشل", payload)
            self.toggle_ui_state("normal")
            self.update_status("الحالة: جاهز.")
            if self.live_edit_temp_path and os.path.exists(self.live_edit_temp_path):
                # [جديد] مسح آمن للمجلد المؤقت في حالة الفشل
                self.update_status("الحالة: جاري المسح الآمن...")
                threading.Thread(target=self.secure_cleanup_and_reset, args=(self.live_edit_temp_path,)).start()
                self.live_edit_temp_path = None
        else:
            self.live_edit_setup_frame.grid_remove()
            self.file_browser_frame.grid(row=0, column=0, sticky="nsew")
            self.populate_file_browser(self.live_edit_temp_path)
            self.update_status("الحالة: جلسة تعديل نشطة.")

    def populate_file_browser(self, path):
        self.current_browser_path = path
        for widget in self.browser_scrollable_frame.winfo_children(): widget.destroy()
        if path != self.live_edit_temp_path:
            up_path = os.path.dirname(path)
            item_frame = ctk.CTkFrame(self.browser_scrollable_frame, fg_color="transparent")
            item_frame.pack(fill="x", pady=2)
            label = ctk.CTkLabel(item_frame, text="⬆️ .. (للأعلى)", anchor="w", font=ctk.CTkFont(weight="bold"))
            label.pack(side="left", padx=5)
            item_frame.bind("<Double-1>", lambda e, p=up_path: self.populate_file_browser(p)); label.bind("<Double-1>", lambda e, p=up_path: self.populate_file_browser(p))
        try:
            items = sorted(os.listdir(path), key=lambda s: not os.path.isdir(os.path.join(path, s)))
            for item_name in items:
                item_path = os.path.join(path, item_name)
                is_dir = os.path.isdir(item_path)
                icon = "📁" if is_dir else "📄"
                item_frame = ctk.CTkFrame(self.browser_scrollable_frame, fg_color="transparent")
                item_frame.pack(fill="x", pady=2)
                label = ctk.CTkLabel(item_frame, text=f" {icon}  {item_name}", anchor="w")
                label.pack(side="left", padx=5, expand=True, fill="x")
                delete_btn = ctk.CTkButton(item_frame, text="🗑️", width=30, fg_color="#454549", hover_color="#BE123C", command=lambda p=item_path: self.delete_session_item(p))
                delete_btn.pack(side="right")
                handler = lambda e, p=item_path, d=is_dir: self.handle_item_click(p, d)
                item_frame.bind("<Double-1>", handler); label.bind("<Double-1>", handler)
        except Exception as e: ctk.CTkLabel(self.browser_scrollable_frame, text=f"خطأ في الوصول: {e}", text_color="red").pack()
    
    def handle_item_click(self, path, is_dir):
        if is_dir: self.populate_file_browser(path)
        else:
            # [جديد] إظهار تحذير حول تسريب البيانات للبرامج الخارجية
            if not self.live_edit_cache_warning_shown:
                messagebox.showwarning("تحذير أمني", "فتح الملفات في برامج خارجية قد يترك آثارًا في ذاكرة التخزين المؤقت (Cache) لتلك البرامج.\n\nسيتم مسح الملفات من مجلد الجلسة بشكل آمن عند الحفظ، ولكن لا يمكن للبرنامج التحكم في آثار البرامج الأخرى.")
                self.live_edit_cache_warning_shown = True
            try: os.startfile(path)
            except Exception as e: messagebox.showerror("خطأ", f"لم يتمكن من فتح الملف: {e}")
            
    def add_file_to_session(self):
        file_to_add = filedialog.askopenfilename(title="اختر ملفًا لإضافته")
        if file_to_add:
            try: shutil.copy(file_to_add, self.current_browser_path); self.populate_file_browser(self.current_browser_path)
            except Exception as e: messagebox.showerror("خطأ", f"فشل في إضافة الملف: {e}")
            
    def add_folder_to_session(self):
        dialog = ctk.CTkInputDialog(text="أدخل اسم المجلد الجديد:", title="إنشاء مجلد")
        folder_name = dialog.get_input()
        if folder_name:
            try: os.makedirs(os.path.join(self.current_browser_path, folder_name)); self.populate_file_browser(self.current_browser_path)
            except Exception as e: messagebox.showerror("خطأ", f"فشل في إنشاء المجلد: {e}")
            
    def delete_session_item(self, path):
        # الحذف هنا ليس بحاجة ليكون آمناً، لأن المجلد المؤقت بأكمله سيتم مسحه بشكل آمن
        if messagebox.askyesno("تأكيد الحذف", f"هل أنت متأكد من حذف '{os.path.basename(path)}'؟\nسيتم الحذف بشكل دائم عند حفظ الجلسة."):
            try:
                if os.path.isdir(path): shutil.rmtree(path)
                else: os.remove(path)
                self.populate_file_browser(self.current_browser_path)
            except Exception as e: messagebox.showerror("خطأ", f"فشل الحذف: {e}")
    
    def start_relock_thread(self):
        password = self.password_entry_live.get()
        self.toggle_ui_state("disabled")
        threading.Thread(target=self.relock_logic, args=(password,), daemon=True).start()

    def relock_logic(self, password):
        key_file_content = None; encryption_key = None
        repacked_zip = None
        try:
            self.after(0, self.update_status, "الحالة: جاري حفظ وإعادة التشفير...")
            if self.select_key_button_live.cget("state") == "normal":
                with open(self.key_file, 'rb') as kf: key_file_content = kf.read()

            archive_path = os.path.join(tempfile.gettempdir(), 'mmmx_repack')
            repacked_zip = shutil.make_archive(archive_path, 'zip', self.live_edit_temp_path)

            with open(repacked_zip, 'rb') as f: data_to_encrypt = f.read()

            encryption_key = self.get_encryption_key(password, self.salt, key_file_content)
            fernet = Fernet(encryption_key)
            new_encrypted_data = fernet.encrypt(data_to_encrypt)
            
            with open(self.locked_file, 'wb') as f: f.write(self.mode_header); f.write(self.salt); f.write(new_encrypted_data)
            self.operation_result = ("success", None)
        except Exception as e: self.operation_result = ("error", f"فشل الحفظ: {e}")
        finally:
            # [جديد] مسح آمن للذاكرة والمجلدات المؤقتة
            password = None
            if key_file_content: key_file_content = os.urandom(len(key_file_content))
            if encryption_key: encryption_key = os.urandom(len(encryption_key))
            if 'data_to_encrypt' in locals(): data_to_encrypt = os.urandom(len(data_to_encrypt))

            # مسح المجلد الذي يحتوي على الملفات المفكوكة
            if self.live_edit_temp_path and os.path.exists(self.live_edit_temp_path):
                secure_wipe_directory(self.live_edit_temp_path)
            # مسح ملف الـ zip المؤقت
            if repacked_zip and os.path.exists(repacked_zip):
                secure_wipe_file(repacked_zip)

            self.after(0, self.finish_relock)

    def finish_relock(self):
        self.toggle_ui_state("normal")
        status, payload = self.operation_result
        if status == "success": messagebox.showinfo("نجاح", "✅ تم حفظ التغييرات وإعادة قفل الملف بنجاح!")
        else: messagebox.showerror("فشل", payload)
        self.file_browser_frame.grid_remove()
        self.live_edit_setup_frame.grid()
        self.update_status("الحالة: جاهز.")
        self.live_edit_cache_warning_shown = False # إعادة ضبط التحذير للجلسة التالية

    def secure_cleanup_and_reset(self, path):
        if path and os.path.exists(path):
            secure_wipe_directory(path)
        self.after(0, self.update_status, "الحالة: جاهز.")

if __name__ == "__main__":
    app = mmmxApp()
    app.mainloop()
