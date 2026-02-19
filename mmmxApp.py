import os
import sys
import shutil
import base64
import tempfile
import threading
import json
import string
import secrets
from datetime import datetime, timedelta
import customtkinter as ctk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from PIL import Image
from tkinterdnd2 import DND_FILES, TkinterDnD

# --- تعريفات أساسية ---
MODE_PASSWORD_ONLY = b'\x01'
MODE_PASSWORD_AND_KEY = b'\x02'
THEME_COLOR = "#00BFFF"
HOVER_COLOR = "#009ACD"
BG_COLOR = "#0A0A0A"
FRAME_COLOR = "#191919"
FILE_FORMAT_SALT_SIZE = 16
FILE_FORMAT_DIGEST_SIZE = 32

# --- إعدادات الحماية من التخمين ---
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_MINUTES = 5

# --- وظائف المسح الآمن ---
def secure_wipe_file(file_path):
    try:
        if os.path.exists(file_path) and os.path.isfile(file_path):
            with open(file_path, "rb+") as f:
                length = os.fstat(f.fileno()).st_size
                if length > 0:
                    f.seek(0); f.write(os.urandom(length))
                    f.seek(0); f.write(b'\x00' * length)
            os.remove(file_path)
    except Exception as e:
        print(f"Secure wipe failed for {file_path}: {e}")

def secure_wipe_directory(path):
    try:
        if not os.path.isdir(path): return
        for root, dirs, files in os.walk(path, topdown=False):
            for name in files: secure_wipe_file(os.path.join(root, name))
            for name in dirs:
                try: os.rmdir(os.path.join(root, name))
                except OSError as e: print(f"Error removing subdir {os.path.join(root, name)}: {e}")
        os.rmdir(path)
    except Exception as e:
        print(f"Error during secure directory wipe for {path}: {e}")

# --- إدارة حالة التطبيق ---
class AppState:
    def __init__(self):
        self.state_file_path = self._get_state_file_path()
        self.state = {
            'failed_attempts': 0, 'lockout_until': None,
            'master_password_hash': None, 'master_password_salt': None,
            'secure_notes': {}
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
                for key in self.state: self.state[key] = data.get(key, self.state[key])
                lockout_str = data.get('lockout_until')
                if lockout_str: self.state['lockout_until'] = datetime.fromisoformat(lockout_str)
        except (FileNotFoundError, json.JSONDecodeError): self.save_state()

    def save_state(self):
        data_to_save = self.state.copy()
        if data_to_save['lockout_until']:
            data_to_save['lockout_until'] = data_to_save['lockout_until'].isoformat()
        with open(self.state_file_path, 'w') as f: json.dump(data_to_save, f, indent=4)

    def set_master_password(self, password):
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600_000)
        self.state['master_password_salt'] = base64.b64encode(salt).decode('utf-8')
        self.state['master_password_hash'] = base64.b64encode(kdf.derive(password.encode())).decode('utf-8')
        self.save_state()

    def verify_master_password(self, password):
        if not self.state['master_password_hash']: return False
        salt = base64.b64decode(self.state['master_password_salt'])
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600_000)
        try:
            kdf.verify(password.encode(), base64.b64decode(self.state['master_password_hash']))
            return True
        except Exception: return False

    def is_locked_out(self):
        if self.state['lockout_until'] and datetime.now() < self.state['lockout_until']: return True
        if self.state['lockout_until'] and datetime.now() >= self.state['lockout_until']: self.record_successful_login()
        return False

    def get_lockout_remaining_str(self):
        if not self.is_locked_out(): return None
        remaining = self.state['lockout_until'] - datetime.now()
        minutes, seconds = divmod(remaining.total_seconds(), 60)
        return f"{int(minutes)}m {int(seconds)}s"

    def record_failed_attempt(self):
        self.state['failed_attempts'] += 1
        if self.state['failed_attempts'] >= MAX_LOGIN_ATTEMPTS:
            self.state['lockout_until'] = datetime.now() + timedelta(minutes=LOCKOUT_MINUTES)
        self.save_state()

    def record_successful_login(self):
        self.state['failed_attempts'] = 0; self.state['lockout_until'] = None
        self.save_state()

# --- نافذة مولد كلمات المرور ---
class PasswordGenerator(ctk.CTkToplevel):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.title("Password Generator"); self.geometry("450x300"); self.transient(); self.attributes("-topmost", True)
        self.grid_columnconfigure(0, weight=1); self.grid_rowconfigure(4, weight=1)
        ctk.CTkLabel(self, text="Password Generator", font=ctk.CTkFont(size=16, weight="bold")).grid(row=0, column=0, padx=20, pady=20, sticky="ew")
        self.password_entry = ctk.CTkEntry(self, font=ctk.CTkFont(size=14), justify="center"); self.password_entry.grid(row=1, column=0, padx=20, pady=10, sticky="ew")
        self.copy_button = ctk.CTkButton(self, text="Copy to Clipboard", command=self.copy_to_clipboard); self.copy_button.grid(row=2, column=0, padx=20, pady=5)
        options_frame = ctk.CTkFrame(self, fg_color="transparent"); options_frame.grid(row=3, column=0, padx=20, pady=10, sticky="ew"); options_frame.grid_columnconfigure(1, weight=1)
        self.length_slider = ctk.CTkSlider(options_frame, from_=8, to=64, number_of_steps=56, command=lambda v: self.length_label.configure(text=f"Length: {int(v)}")); self.length_slider.set(16)
        self.length_label = ctk.CTkLabel(options_frame, text="Length: 16")
        self.use_uppercase = ctk.CTkCheckBox(options_frame, text="A-Z"); self.use_uppercase.select()
        self.use_lowercase = ctk.CTkCheckBox(options_frame, text="a-z"); self.use_lowercase.select()
        self.use_numbers = ctk.CTkCheckBox(options_frame, text="0-9"); self.use_numbers.select()
        self.use_symbols = ctk.CTkCheckBox(options_frame, text="!@#$"); self.use_symbols.select()
        self.length_label.grid(row=0, column=0, padx=5); self.length_slider.grid(row=0, column=1, padx=5, sticky="ew")
        self.use_uppercase.grid(row=1, column=0, columnspan=2, padx=5, pady=5, sticky="w"); self.use_lowercase.grid(row=2, column=0, columnspan=2, padx=5, pady=5, sticky="w")
        self.use_numbers.grid(row=3, column=0, columnspan=2, padx=5, pady=5, sticky="w"); self.use_symbols.grid(row=4, column=0, columnspan=2, padx=5, pady=5, sticky="w")
        self.generate_button = ctk.CTkButton(self, text="Generate New Password", height=40, command=self.generate_password); self.generate_button.grid(row=4, column=0, padx=20, pady=20, sticky="ew")
        self.generate_password()

    def generate_password(self):
        chars = ( (string.ascii_uppercase if self.use_uppercase.get() else '') + (string.ascii_lowercase if self.use_lowercase.get() else '') +
                  (string.digits if self.use_numbers.get() else '') + (string.punctuation if self.use_symbols.get() else '') )
        if not chars: self.password_entry.delete(0, "end"); self.password_entry.insert(0, "Select a character set"); return
        password = ''.join(secrets.choice(chars) for _ in range(int(self.length_slider.get())))
        self.password_entry.delete(0, "end"); self.password_entry.insert(0, password)
        
    def copy_to_clipboard(self):
        self.clipboard_clear(); self.clipboard_append(self.password_entry.get())
        self.copy_button.configure(text="Copied!"); self.after(2000, lambda: self.copy_button.configure(text="Copy to Clipboard"))

# --- التطبيق الرئيسي ---
class mmmxApp(ctk.CTk, TkinterDnD.DnDWrapper):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.TkdndVersion = TkinterDnD._require(self)
        self.title("mmmx"); self.geometry("950x700"); self.attributes('-alpha', 0.0)
        self.app_state = AppState(); self.password_generator_window = None
        try:
            self.icon_path = self.resource_path("icon.ico"); self.iconbitmap(self.icon_path)
            self.app_icon_large = ctk.CTkImage(Image.open(self.icon_path), size=(128, 128))
            self.app_icon_small = ctk.CTkImage(Image.open(self.icon_path), size=(64, 64))
        except Exception as e: print(f"Icon Error: {e}"); self.app_icon_large, self.app_icon_small = None, None
        
        # Center window on screen
        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f'{width}x{height}+{x}+{y}')

        if not self.app_state.state.get('master_password_hash'): self.setup_initial_password_screen()
        else: self.setup_login_screen()

        self.after(200, self.fade_in, 0.0)
        self.source_path, self.locked_file, self.key_file, self.operation_result, self.live_edit_temp_path = "", "", "", None, None
        self.live_edit_cache_warning_shown = False; self.master_password = None

    # --- [مُعدل] دالة الظهور التدريجي مع إصلاح التركيز ---
    def fade_in(self, alpha=0.0):
        if alpha < 1:
            alpha += 0.1  # A bit faster fade-in
            self.attributes('-alpha', alpha)
            self.after(15, lambda: self.fade_in(alpha))
        else:
            # --- هذا هو الجزء الجديد والمهم ---
            self.attributes('-alpha', 1.0) # 1. التأكد من أن الشفافية 100%
            self.deiconify()               # 2. إظهار النافذة (ضد التصغير)
            self.lift()                    # 3. رفع النافذة للأمام
            self.focus_force()             # 4. إجبار نظام التشغيل على التركيز عليها
            # ------------------------------------
    
    def setup_initial_password_screen(self):
        self.initial_setup_frame = ctk.CTkFrame(self, fg_color=BG_COLOR, corner_radius=0); self.initial_setup_frame.pack(fill="both", expand=True)
        ctk.CTkLabel(self.initial_setup_frame, text="Welcome to mmmx", font=ctk.CTkFont(size=24, weight="bold")).pack(pady=(150, 20))
        ctk.CTkLabel(self.initial_setup_frame, text="Please create a strong master password to secure your data.").pack(pady=10)
        self.new_pass_entry = ctk.CTkEntry(self.initial_setup_frame, placeholder_text="New Master Password", show="*", width=300, height=45)
        self.confirm_pass_entry = ctk.CTkEntry(self.initial_setup_frame, placeholder_text="Confirm Master Password", show="*", width=300, height=45)
        self.setup_button = ctk.CTkButton(self.initial_setup_frame, text="Save and Start", command=self.save_initial_password, width=300, height=45)
        self.setup_error_label = ctk.CTkLabel(self.initial_setup_frame, text="", text_color="#FF4D4D")
        self.new_pass_entry.pack(pady=10); self.confirm_pass_entry.pack(pady=10); self.setup_button.pack(pady=20); self.setup_error_label.pack(pady=5)

    def save_initial_password(self):
        new_pass = self.new_pass_entry.get(); confirm_pass = self.confirm_pass_entry.get()
        if not new_pass or len(new_pass) < 8: self.setup_error_label.configure(text="Password must be at least 8 characters long."); return
        if new_pass != confirm_pass: self.setup_error_label.configure(text="Passwords do not match."); return
        self.app_state.set_master_password(new_pass); self.master_password = new_pass; self.fade_out_and_setup_main_ui()

    def setup_login_screen(self):
        self.login_frame = ctk.CTkFrame(self, fg_color=BG_COLOR, corner_radius=0); self.login_frame.pack(fill="both", expand=True)
        self.icon_label = ctk.CTkLabel(self.login_frame, text="", image=self.app_icon_large); self.icon_label.pack(pady=(150, 20))
        ctk.CTkLabel(self.login_frame, text="mmmx", font=ctk.CTkFont(size=32, weight="bold", family="Impact")).pack(pady=10)
        self.password_entry_login = ctk.CTkEntry(self.login_frame, placeholder_text="ENTER MASTER PASSWORD", show="*", height=45, width=300, justify="center"); self.password_entry_login.pack(pady=20)
        self.login_button = ctk.CTkButton(self.login_frame, text="UNLOCK", height=45, width=300, command=self.check_login); self.login_button.pack(pady=10)
        self.error_label_login = ctk.CTkLabel(self.login_frame, text="", text_color="#FF4D4D"); self.error_label_login.pack(pady=10)
        self.password_entry_login.bind("<Return>", self.check_login)
        if self.app_state.is_locked_out(): self.show_lockout_message()

    def show_lockout_message(self):
        remaining_time = self.app_state.get_lockout_remaining_str()
        if remaining_time:
            self.error_label_login.configure(text=f"ACCESS LOCKED. TRY AGAIN IN {remaining_time}")
            self.login_button.configure(state="disabled"); self.password_entry_login.configure(state="disabled")
            self.after(1000, self.show_lockout_message)
        else: self.error_label_login.configure(text=""); self.login_button.configure(state="normal"); self.password_entry_login.configure(state="normal")

    def check_login(self, event=None):
        if self.app_state.is_locked_out(): self.show_lockout_message(); return
        entered_password = self.password_entry_login.get()
        if self.app_state.verify_master_password(entered_password):
            self.master_password = entered_password; self.app_state.record_successful_login(); self.fade_out_and_setup_main_ui()
        else:
            self.app_state.record_failed_attempt()
            if self.app_state.is_locked_out(): self.show_lockout_message()
            else: self.error_label_login.configure(text=f"ACCESS DENIED. {MAX_LOGIN_ATTEMPTS - self.app_state.state['failed_attempts']} ATTEMPTS REMAINING.")

    def fade_out_and_setup_main_ui(self, alpha=1.0):
        if alpha > 0: self.attributes('-alpha', alpha); self.after(25, lambda: self.fade_out_and_setup_main_ui(alpha - 0.1))
        else:
            for widget in self.winfo_children(): widget.destroy()
            self.setup_main_ui(); self.fade_in(0.0)

    def setup_main_ui(self):
        self.grid_columnconfigure(1, weight=1); self.grid_rowconfigure(0, weight=1)
        self.sidebar_frame = ctk.CTkFrame(self, width=220, fg_color=BG_COLOR, corner_radius=0); self.sidebar_frame.grid(row=0, column=0, sticky="nsw"); self.sidebar_frame.grid_rowconfigure(5, weight=1)
        ctk.CTkLabel(self.sidebar_frame, text="", image=self.app_icon_small).grid(row=0, column=0, pady=30, padx=20)
        ctk.CTkLabel(self.sidebar_frame, text="mmmx", font=ctk.CTkFont(size=40, weight="bold", family="Impact")).grid(row=1, column=0, padx=20, pady=(0, 20))
        ctk.CTkButton(self.sidebar_frame, text="Password Generator", command=self.open_password_generator).grid(row=4, column=0, padx=20, pady=10)
        self.status_label = ctk.CTkLabel(self.sidebar_frame, text="Status: Ready", anchor="w", text_color="gray"); self.status_label.grid(row=6, column=0, padx=20, pady=10, sticky="sw")
        self.progress_bar = ctk.CTkProgressBar(self.sidebar_frame, mode='indeterminate')
        self.main_frame = ctk.CTkFrame(self, fg_color=FRAME_COLOR, corner_radius=0); self.main_frame.grid(row=0, column=1, sticky="nsew"); self.main_frame.grid_rowconfigure(0, weight=1); self.main_frame.grid_columnconfigure(0, weight=1)
        self.tabview = ctk.CTkTabview(self.main_frame, fg_color="transparent", border_width=0); self.tabview.grid(row=0, column=0, padx=20, pady=20, sticky="nsew"); self.tabview.configure(segmented_button_selected_color=THEME_COLOR, segmented_button_selected_hover_color=HOVER_COLOR)
        self.tabview.add("🔒 Encrypt"); self.tabview.add("🔑 Decrypt"); self.tabview.add("📝 Secure Notes"); self.tabview.add("🚀 Live Edit")
        self.setup_operation_ui(self.tabview.tab("🔒 Encrypt"), "encrypt"); self.setup_operation_ui(self.tabview.tab("🔑 Decrypt"), "decrypt")
        self.setup_secure_notes_ui(self.tabview.tab("📝 Secure Notes")); self.setup_operation_ui(self.tabview.tab("🚀 Live Edit"), "live_edit")
        self.drop_target_register(DND_FILES); self.dnd_bind('<<Drop>>', self.handle_drop)

    def handle_drop(self, event):
        path = event.data.strip('{}');
        if os.path.exists(path):
            self.tabview.set("🔒 Encrypt"); self.source_path = path
            self.path_label_enc.configure(text=f"Selected: {os.path.basename(path)}")

    def setup_secure_notes_ui(self, tab):
        tab.grid_columnconfigure(1, weight=1); tab.grid_rowconfigure(1, weight=1)
        self.notes_list_frame = ctk.CTkScrollableFrame(tab, label_text="Your Notes", width=200); self.notes_list_frame.grid(row=0, column=0, rowspan=3, padx=10, pady=10, sticky="nsw")
        self.note_title_entry = ctk.CTkEntry(tab, placeholder_text="Note Title"); self.note_title_entry.grid(row=0, column=1, padx=10, pady=10, sticky="new")
        self.note_content_box = ctk.CTkTextbox(tab, wrap="word", font=ctk.CTkFont(size=14)); self.note_content_box.grid(row=1, column=1, padx=10, pady=0, sticky="nsew")
        buttons_frame = ctk.CTkFrame(tab, fg_color="transparent"); buttons_frame.grid(row=2, column=1, padx=10, pady=10, sticky="ew")
        self.save_note_button = ctk.CTkButton(buttons_frame, text="Save Note", command=self.save_note); self.save_note_button.pack(side="right", padx=5)
        self.delete_note_button = ctk.CTkButton(buttons_frame, text="Delete Note", fg_color="#D22B2B", hover_color="#AA2222", command=self.delete_note); self.delete_note_button.pack(side="right", padx=5)
        self.refresh_notes_list()

    def refresh_notes_list(self):
        for widget in self.notes_list_frame.winfo_children(): widget.destroy()
        notes = self.app_state.state.get('secure_notes', {})
        for title in sorted(notes.keys()):
            btn = ctk.CTkButton(self.notes_list_frame, text=title, fg_color="transparent", anchor="w", command=lambda t=title: self.load_note(t))
            btn.pack(fill="x", pady=2)

    def get_notes_fernet(self):
        notes_salt = b'mmmx_secure_notes_salt_!@#'; kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=notes_salt, iterations=100_000)
        return Fernet(base64.urlsafe_b64encode(kdf.derive(self.master_password.encode())))

    def save_note(self):
        title = self.note_title_entry.get(); content = self.note_content_box.get("1.0", "end-1c")
        if not title or not content: messagebox.showerror("Error", "Title and content cannot be empty."); return
        self.app_state.state['secure_notes'][title] = self.get_notes_fernet().encrypt(content.encode()).decode('utf-8')
        self.app_state.save_state(); self.refresh_notes_list(); messagebox.showinfo("Success", f"Note '{title}' saved securely.")

    def load_note(self, title):
        encrypted_content = self.app_state.state['secure_notes'].get(title);
        if not encrypted_content: return
        try:
            decrypted_content = self.get_notes_fernet().decrypt(encrypted_content.encode()).decode('utf-8')
            self.note_title_entry.delete(0, "end"); self.note_title_entry.insert(0, title)
            self.note_content_box.delete("1.0", "end"); self.note_content_box.insert("1.0", decrypted_content)
        except Exception: messagebox.showerror("Error", "Failed to decrypt note. Master password may have changed or data is corrupt.")

    def delete_note(self):
        title = self.note_title_entry.get()
        if not title in self.app_state.state['secure_notes']: messagebox.showerror("Error", "Note not found to delete."); return
        if messagebox.askyesno("Confirm Delete", f"Are you sure you want to permanently delete '{title}'?"):
            del self.app_state.state['secure_notes'][title]; self.app_state.save_state()
            self.note_title_entry.delete(0, "end"); self.note_content_box.delete("1.0", "end"); self.refresh_notes_list()

    def open_password_generator(self):
        if self.password_generator_window is None or not self.password_generator_window.winfo_exists():
            self.password_generator_window = PasswordGenerator(self)
        self.password_generator_window.focus()

    def setup_operation_ui(self, tab, mode):
        tab.grid_columnconfigure(0, weight=1)
        if mode == "encrypt":
            ctk.CTkLabel(tab, text="Secure a File or Folder", font=ctk.CTkFont(size=22, weight="bold")).grid(row=0, column=0, padx=30, pady=20)
            ctk.CTkLabel(tab, text="Drag & Drop File/Folder Here or...", text_color="gray", font=ctk.CTkFont(size=14)).grid(row=1, column=0, padx=30, pady=5)
            ctk.CTkButton(tab, text="📂  Select...", command=self.select_path_to_encrypt).grid(row=2, column=0, padx=30, pady=10, sticky="w")
            self.path_label_enc = ctk.CTkLabel(tab, text="Nothing selected", text_color="gray", anchor="w"); self.path_label_enc.grid(row=3, column=0, padx=30, pady=5, sticky="ew")
            self.password_entry_enc = ctk.CTkEntry(tab, placeholder_text="Password (optional, uses master if empty)", show="*", height=40); self.password_entry_enc.grid(row=4, column=0, padx=30, pady=20, sticky="ew")
            self.use_keyfile_check = ctk.CTkCheckBox(tab, text="Extra Security: Use a Keyfile", font=ctk.CTkFont(weight="bold")); self.use_keyfile_check.select(); self.use_keyfile_check.grid(row=5, column=0, padx=30, pady=10, sticky="w")
            self.encrypt_button = ctk.CTkButton(tab, text="🔒  Encrypt", height=50, command=self.start_encryption_thread); self.encrypt_button.grid(row=6, column=0, padx=30, pady=(30, 20), sticky="ew")
        elif mode == "decrypt":
            ctk.CTkLabel(tab, text="Decrypt File", font=ctk.CTkFont(size=22, weight="bold")).grid(row=0, column=0, padx=30, pady=20)
            ctk.CTkButton(tab, text="📂 Select Encrypted File...", command=lambda: self.select_file_to_decrypt(live_edit=False)).grid(row=1, column=0, padx=30, pady=(10, 5), sticky="ew")
            self.locked_file_label_dec = ctk.CTkLabel(tab, text="...", text_color="gray"); self.locked_file_label_dec.grid(row=2, column=0, padx=30, pady=(0, 15), sticky="w")
            self.select_key_button_dec = ctk.CTkButton(tab, text="🔑 Select Keyfile...", command=lambda: self.select_key_file(live_edit=False)); self.select_key_button_dec.grid(row=3, column=0, padx=30, pady=(10, 5), sticky="ew")
            self.key_file_label_dec = ctk.CTkLabel(tab, text="...", text_color="gray"); self.key_file_label_dec.grid(row=4, column=0, padx=30, pady=(0, 15), sticky="w")
            self.password_entry_dec = ctk.CTkEntry(tab, placeholder_text="Password (uses master if empty)", show="*", height=40); self.password_entry_dec.grid(row=5, column=0, padx=30, pady=15, sticky="ew")
            self.decrypt_button = ctk.CTkButton(tab, text="🔑  Decrypt", height=50, command=self.start_decryption_thread); self.decrypt_button.grid(row=6, column=0, padx=30, pady=(20, 15), sticky="ew")
        elif mode == "live_edit":
            self.live_edit_setup_frame = ctk.CTkFrame(tab, fg_color="transparent"); self.live_edit_setup_frame.grid(row=0, column=0, sticky="nsew", padx=30, pady=20); self.live_edit_setup_frame.grid_columnconfigure(0, weight=1)
            ctk.CTkLabel(self.live_edit_setup_frame, text="Live Edit Session", font=ctk.CTkFont(size=22, weight="bold")).grid(row=0, column=0, pady=20)
            ctk.CTkButton(self.live_edit_setup_frame, text="📂 Select Encrypted File...", command=lambda: self.select_file_to_decrypt(live_edit=True)).grid(row=1, column=0, pady=(10, 5), sticky="ew")
            self.live_edit_file_label = ctk.CTkLabel(self.live_edit_setup_frame, text="...", text_color="gray"); self.live_edit_file_label.grid(row=2, column=0, pady=(0, 15), sticky="w")
            self.select_key_button_live = ctk.CTkButton(self.live_edit_setup_frame, text="🔑 Select Keyfile...", command=lambda: self.select_key_file(live_edit=True)); self.select_key_button_live.grid(row=3, column=0, pady=(10, 5), sticky="ew")
            self.live_edit_key_label = ctk.CTkLabel(self.live_edit_setup_frame, text="...", text_color="gray"); self.live_edit_key_label.grid(row=4, column=0, pady=(0, 15), sticky="w")
            self.password_entry_live = ctk.CTkEntry(self.live_edit_setup_frame, placeholder_text="Password (uses master if empty)", show="*", height=40); self.password_entry_live.grid(row=5, column=0, pady=15, sticky="ew")
            self.live_edit_button = ctk.CTkButton(self.live_edit_setup_frame, text="🚀  Start Session", height=50, command=self.start_live_edit_thread); self.live_edit_button.grid(row=6, column=0, pady=(20, 15), sticky="ew")
            self.file_browser_frame = ctk.CTkFrame(tab, fg_color="transparent"); self.file_browser_frame.grid_columnconfigure(0, weight=1); self.file_browser_frame.grid_rowconfigure(1, weight=1)
            browser_controls_frame = ctk.CTkFrame(self.file_browser_frame, fg_color="transparent"); browser_controls_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
            ctk.CTkButton(browser_controls_frame, text="➕ Add File", command=self.add_file_to_session).pack(side="left", padx=5)
            ctk.CTkButton(browser_controls_frame, text="📁 New Folder", command=self.add_folder_to_session).pack(side="left", padx=5)
            self.relock_button = ctk.CTkButton(browser_controls_frame, text="💾 Save & Relock", font=ctk.CTkFont(weight="bold"), fg_color="red", hover_color="#B91C1C", command=self.start_relock_thread); self.relock_button.pack(side="right", padx=5)
            self.browser_scrollable_frame = ctk.CTkScrollableFrame(self.file_browser_frame, label_text="Session Contents"); self.browser_scrollable_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=5); self.current_browser_path = ""

    def get_encryption_key(self, password, salt, key_file_content=None):
        base_secret = password.encode()
        if key_file_content: base_secret += key_file_content
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=1_200_000)
        return base64.urlsafe_b64encode(kdf.derive(base_secret))
        
    def start_encryption_thread(self):
        password = self.password_entry_enc.get() or self.master_password
        if not self.source_path: messagebox.showerror("Error", "Please select a file/folder."); return
        if not password: messagebox.showerror("Error", "A password is required."); return
        key_file_path = None
        if self.use_keyfile_check.get():
            key_file_path = filedialog.asksaveasfilename(defaultextension=".key", filetypes=[("Key Files", "*.key")], title="Save Keyfile")
            if not key_file_path: return
        self.toggle_ui_state("disabled")
        threading.Thread(target=self.encrypt_logic, args=(password, key_file_path), daemon=True).start()

    def encrypt_logic(self, password, key_file_path):
        temp_dir = None
        try:
            key_file_content = None
            mode_header = MODE_PASSWORD_ONLY
            if key_file_path:
                key_file_content = os.urandom(32);
                with open(key_file_path, 'wb') as kf: kf.write(key_file_content)
                mode_header = MODE_PASSWORD_AND_KEY
            self.after(0, self.update_status, "Status: Compressing...")
            is_dir = os.path.isdir(self.source_path)
            source_data_path = shutil.make_archive(os.path.join(tempfile.mkdtemp(), 'archive'), 'zip', self.source_path) if is_dir else self.source_path
            if is_dir: temp_dir = os.path.dirname(source_data_path)
            with open(source_data_path, 'rb') as f: data_to_encrypt = f.read()
            data_hasher = hashes.Hash(hashes.SHA256()); data_hasher.update(data_to_encrypt); data_digest = data_hasher.finalize()
            self.after(0, self.update_status, "Status: Encrypting...")
            salt = os.urandom(16)
            fernet = Fernet(self.get_encryption_key(password, salt, key_file_content))
            encrypted_data = fernet.encrypt(data_to_encrypt)
            with open(self.source_path + ".locked", 'wb') as f: f.write(mode_header); f.write(salt); f.write(data_digest); f.write(encrypted_data)
            self.operation_result = ("success", is_dir)
        except Exception as e: self.operation_result = ("error", f"Encryption failed: {e}")
        finally:
            if temp_dir: shutil.rmtree(temp_dir)
            self.after(0, self.finish_encryption)

    def finish_encryption(self):
        self.toggle_ui_state("normal")
        status, payload = self.operation_result
        if status == "success":
            messagebox.showinfo("Success", "✅ Encryption successful!")
            if messagebox.askyesno("Confirm", "Securely wipe original file/folder?"):
                self.update_status("Status: Wiping original..."); self.toggle_ui_state("disabled")
                threading.Thread(target=self.wipe_original_and_update, args=(self.source_path, payload)).start()
        elif status == "error": messagebox.showerror("Failure", payload)
        if status != "success" or not messagebox.askyesno: self.update_status("Status: Ready.")

    def wipe_original_and_update(self, path, is_dir):
        if is_dir: secure_wipe_directory(path)
        else: secure_wipe_file(path)
        self.after(0, self.update_status, "Status: Ready.")
        self.after(0, self.toggle_ui_state, "normal")

    def resource_path(self, relative_path):
        try: base_path = sys._MEIPASS
        except Exception: base_path = os.path.abspath(".")
        return os.path.join(base_path, relative_path)

    def update_status(self, text):
        if self.status_label.winfo_exists(): self.status_label.configure(text=text)
        
    def toggle_ui_state(self, state="disabled"):
        is_disabled = state == "disabled"
        for widget in [self.encrypt_button, self.decrypt_button, self.live_edit_button, self.tabview]:
            if widget and widget.winfo_exists(): widget.configure(state=state)
        if is_disabled: self.progress_bar.grid(row=7, column=0, padx=20, pady=10, sticky="sew"); self.progress_bar.start()
        else: self.progress_bar.stop(); self.progress_bar.grid_forget()

    def select_path_to_encrypt(self):
        path = filedialog.askdirectory(title="Select Folder") or filedialog.askopenfilename(title="Or Select File")
        if path: self.source_path = path; self.path_label_enc.configure(text=os.path.basename(path))

    def select_file_to_decrypt(self, live_edit=False):
        path = filedialog.askopenfilename(title="Select Locked File", filetypes=[("mmmx Locked File", "*.locked")])
        if not path: return
        self.locked_file = path
        label = self.live_edit_file_label if live_edit else self.locked_file_label_dec; label.configure(text=os.path.basename(path))
        with open(path, 'rb') as f: mode_header = f.read(1)
        key_button = self.select_key_button_live if live_edit else self.select_key_button_dec
        key_label = self.live_edit_key_label if live_edit else self.key_file_label_dec
        if mode_header == MODE_PASSWORD_ONLY: key_button.configure(state="disabled", text="No keyfile required"); key_label.configure(text="")
        else: key_button.configure(state="normal", text="🔑 Select Keyfile..."); key_label.configure(text="Waiting for keyfile...")

    def select_key_file(self, live_edit=False):
        path = filedialog.askopenfilename(title="Select Keyfile", filetypes=[("Key Files", "*.key")])
        if path:
            self.key_file = path
            label = self.live_edit_key_label if live_edit else self.key_file_label_dec; label.configure(text=os.path.basename(path))
            
    def start_decryption_thread(self):
        password = self.password_entry_dec.get() or self.master_password
        if not self.locked_file: messagebox.showerror("Error", "Please select a file."); return
        if not password: messagebox.showerror("Error", "A password is required."); return
        self.toggle_ui_state("disabled")
        threading.Thread(target=self.decrypt_logic, args=(password, False), daemon=True).start()

    def decrypt_logic(self, password, is_live_edit):
        try:
            self.after(0, self.update_status, "Status: Decrypting...")
            key_file_content = None
            if self.select_key_button_dec.cget("state") == "normal" or (is_live_edit and self.select_key_button_live.cget("state") == "normal"):
                if not self.key_file: self.operation_result = ("error", "Keyfile is required but not selected."); return
                with open(self.key_file, 'rb') as kf: key_file_content = kf.read()
            with open(self.locked_file, 'rb') as f:
                self.mode_header = f.read(1); self.salt = f.read(16); stored_digest = f.read(32); encrypted_data = f.read()
            fernet = Fernet(self.get_encryption_key(password, self.salt, key_file_content))
            decrypted_data = fernet.decrypt(encrypted_data)
            new_hasher = hashes.Hash(hashes.SHA256()); new_hasher.update(decrypted_data); new_digest = new_hasher.finalize()
            if new_digest != stored_digest:
                self.after(0, messagebox.showwarning, "Data Integrity Warning", "The file's checksum does not match. It may be corrupt or tampered with.")
            self.operation_result = ("success", decrypted_data)
        except Exception as e: self.operation_result = ("error", f"Decryption failed. Check password/keyfile or file is corrupt. Error: {e}")
        finally:
            callback = self.finish_live_edit_setup if is_live_edit else self.finish_decryption
            self.after(0, callback)

    def finish_decryption(self):
        self.toggle_ui_state("normal"); status, payload = self.operation_result
        if status == "success":
            output_folder = filedialog.askdirectory(title="Select folder to save decrypted file(s)")
            if not output_folder: self.update_status("Status: Ready."); return
            final_output_path = os.path.join(output_folder, os.path.basename(self.locked_file).replace(".locked", ""))
            try:
                with tempfile.NamedTemporaryFile(delete=False) as tmp: tmp.write(payload); tmp_path = tmp.name
                shutil.unpack_archive(tmp_path, final_output_path); os.remove(tmp_path)
            except:
                with open(final_output_path, 'wb') as f: f.write(payload)
            messagebox.showinfo("Success", f"✅ Decryption successful!\nSaved to: {final_output_path}")
        elif status == "error": messagebox.showerror("Failure", payload)
        self.update_status("Status: Ready.")

    def start_live_edit_thread(self):
        password = self.password_entry_live.get() or self.master_password
        if not self.locked_file: messagebox.showerror("Error", "Please select a file."); return
        if not password: messagebox.showerror("Error", "A password is required."); return
        self.toggle_ui_state("disabled")
        threading.Thread(target=self.decrypt_logic, args=(password, True), daemon=True).start()

    def finish_live_edit_setup(self):
        status, payload = self.operation_result
        if status == "error":
            messagebox.showerror("Failure", payload); self.toggle_ui_state("normal"); self.update_status("Status: Ready.")
            return
        self.live_edit_temp_path = tempfile.mkdtemp(prefix="mmmx_")
        try:
            with tempfile.NamedTemporaryFile(delete=False) as tmp: tmp.write(payload); tmp_path = tmp.name
            shutil.unpack_archive(tmp_path, self.live_edit_temp_path); os.remove(tmp_path)
        except:
            file_path = os.path.join(self.live_edit_temp_path, os.path.basename(self.locked_file).replace(".locked", ""))
            with open(file_path, 'wb') as f: f.write(payload)
        self.live_edit_setup_frame.grid_remove(); self.file_browser_frame.grid(row=0, column=0, sticky="nsew")
        self.populate_file_browser(self.live_edit_temp_path); self.update_status("Status: Live edit session active.")
    
    def populate_file_browser(self, path):
        self.current_browser_path = path
        for widget in self.browser_scrollable_frame.winfo_children(): widget.destroy()
        if path != self.live_edit_temp_path:
            up_path = os.path.dirname(path)
            label = ctk.CTkLabel(self.browser_scrollable_frame, text="⬆️ .. (Up)", anchor="w", font=ctk.CTkFont(weight="bold"))
            label.pack(fill="x", pady=2); label.bind("<Double-1>", lambda e, p=up_path: self.populate_file_browser(p))
        try:
            items = sorted(os.listdir(path), key=lambda s: not os.path.isdir(os.path.join(path, s)))
            for item_name in items:
                item_path = os.path.join(path, item_name); is_dir = os.path.isdir(item_path); icon = "📁" if is_dir else "📄"
                item_frame = ctk.CTkFrame(self.browser_scrollable_frame, fg_color="transparent"); item_frame.pack(fill="x", pady=2)
                label = ctk.CTkLabel(item_frame, text=f" {icon}  {item_name}", anchor="w"); label.pack(side="left", padx=5, expand=True, fill="x")
                ctk.CTkButton(item_frame, text="🗑️", width=30, fg_color="#454549", hover_color="#BE123C", command=lambda p=item_path: self.delete_session_item(p)).pack(side="right")
                handler = lambda e, p=item_path, d=is_dir: self.handle_item_click(p, d)
                item_frame.bind("<Double-1>", handler); label.bind("<Double-1>", handler)
        except Exception as e: ctk.CTkLabel(self.browser_scrollable_frame, text=f"Access Error: {e}", text_color="red").pack()
    
    def handle_item_click(self, path, is_dir):
        if is_dir: self.populate_file_browser(path)
        else:
            if not self.live_edit_cache_warning_shown:
                messagebox.showwarning("Security Warning", "Opening files in external programs may leave traces in their cache.\nThese traces are not managed by mmmx.")
                self.live_edit_cache_warning_shown = True
            try: os.startfile(path)
            except Exception as e: messagebox.showerror("Error", f"Could not open file: {e}")

    def add_file_to_session(self):
        file_to_add = filedialog.askopenfilename(title="Select file to add")
        if file_to_add:
            try: shutil.copy(file_to_add, self.current_browser_path); self.populate_file_browser(self.current_browser_path)
            except Exception as e: messagebox.showerror("Error", f"Failed to add file: {e}")

    def add_folder_to_session(self):
        dialog = ctk.CTkInputDialog(text="Enter new folder name:", title="Create Folder")
        folder_name = dialog.get_input()
        if folder_name:
            try: os.makedirs(os.path.join(self.current_browser_path, folder_name)); self.populate_file_browser(self.current_browser_path)
            except Exception as e: messagebox.showerror("Error", f"Failed to create folder: {e}")

    def delete_session_item(self, path):
        if messagebox.askyesno("Confirm Delete", f"Permanently delete '{os.path.basename(path)}'?"):
            try:
                if os.path.isdir(path): shutil.rmtree(path)
                else: os.remove(path)
                self.populate_file_browser(self.current_browser_path)
            except Exception as e: messagebox.showerror("Error", f"Deletion failed: {e}")
    
    def start_relock_thread(self):
        password = self.password_entry_live.get() or self.master_password
        self.toggle_ui_state("disabled")
        threading.Thread(target=self.relock_logic, args=(password,), daemon=True).start()

    def relock_logic(self, password):
        try:
            self.after(0, self.update_status, "Status: Saving and relocking...")
            key_file_content = None
            if self.select_key_button_live.cget("state") == "normal":
                with open(self.key_file, 'rb') as kf: key_file_content = kf.read()
            repacked_zip = shutil.make_archive(os.path.join(tempfile.gettempdir(), 'mmmx_repack'), 'zip', self.live_edit_temp_path)
            with open(repacked_zip, 'rb') as f: data_to_encrypt = f.read()
            data_hasher = hashes.Hash(hashes.SHA256()); data_hasher.update(data_to_encrypt); data_digest = data_hasher.finalize()
            fernet = Fernet(self.get_encryption_key(password, self.salt, key_file_content))
            new_encrypted_data = fernet.encrypt(data_to_encrypt)
            with open(self.locked_file, 'wb') as f: f.write(self.mode_header); f.write(self.salt); f.write(data_digest); f.write(new_encrypted_data)
            self.operation_result = ("success", None)
        except Exception as e: self.operation_result = ("error", f"Relock failed: {e}")
        finally:
            if self.live_edit_temp_path and os.path.exists(self.live_edit_temp_path): secure_wipe_directory(self.live_edit_temp_path)
            if 'repacked_zip' in locals() and os.path.exists(repacked_zip): secure_wipe_file(repacked_zip)
            self.after(0, self.finish_relock)

    def finish_relock(self):
        self.toggle_ui_state("normal"); status, payload = self.operation_result
        if status == "success": messagebox.showinfo("Success", "✅ Changes saved and file relocked successfully!")
        else: messagebox.showerror("Failure", payload)
        self.file_browser_frame.grid_remove(); self.live_edit_setup_frame.grid()
        self.update_status("Status: Ready."); self.live_edit_cache_warning_shown = False
    
if __name__ == "__main__":
    app = mmmxApp()
    app.mainloop()

