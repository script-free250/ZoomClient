import os
import sys
import shutil
import base64
import tempfile
import threading
import customtkinter as ctk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# --- تعريفات أساسية ---
MODE_PASSWORD_ONLY = b'\x01'
MODE_PASSWORD_AND_KEY = b'\x02'
THEME_COLOR = "#0D9488" # Teal-500
BG_COLOR = "#1C1917"   # Warm Dark Gray
FRAME_COLOR = "#292524" # Slightly Lighter Gray

# --- إعدادات المظهر ---
ctk.set_appearance_mode("Dark")

class AegisApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Aegis")
        self.geometry("850x650")
        self.attributes('-alpha', 0.0)

        try:
            icon_path = self.resource_path("icon.ico")
            self.iconbitmap(icon_path)
        except Exception: pass

        # --- التصميم ---
        self.grid_columnconfigure(1, weight=1); self.grid_rowconfigure(0, weight=1)
        self.sidebar_frame = ctk.CTkFrame(self, width=220, fg_color=BG_COLOR, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsw")
        self.sidebar_frame.grid_rowconfigure(4, weight=1)
        
        logo_label = ctk.CTkLabel(self.sidebar_frame, text="AEGIS", font=ctk.CTkFont(size=36, weight="bold", family="Impact"))
        logo_label.grid(row=0, column=0, padx=20, pady=(40, 20))
        self.status_label = ctk.CTkLabel(self.sidebar_frame, text="الحالة: جاهز", anchor="w", text_color="gray")
        self.status_label.grid(row=5, column=0, padx=20, pady=10, sticky="sw")
        self.progress_bar = ctk.CTkProgressBar(self.sidebar_frame, mode='indeterminate', progress_color=THEME_COLOR)

        self.main_frame = ctk.CTkFrame(self, fg_color=FRAME_COLOR, corner_radius=0)
        self.main_frame.grid(row=0, column=1, sticky="nsew")
        self.main_frame.grid_rowconfigure(0, weight=1); self.main_frame.grid_columnconfigure(0, weight=1)

        self.tabview = ctk.CTkTabview(self.main_frame, fg_color=FRAME_COLOR, border_width=2, border_color=BG_COLOR)
        self.tabview.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")
        self.tabview.configure(segmented_button_selected_color=THEME_COLOR, segmented_button_selected_hover_color="#14B8A6", segmented_button_unselected_hover_color="#52525B")
        
        self.tabview.add("🔒  تشفير")
        self.tabview.add("🔑  فك تشفير")
        self.tabview.add("🛡️  تعديل مباشر")
        
        self.setup_encrypt_decrypt_ui(self.tabview.tab("🔒  تشفير"), "encrypt")
        self.setup_encrypt_decrypt_ui(self.tabview.tab("🔑  فك تشفير"), "decrypt")
        self.setup_live_edit_ui(self.tabview.tab("🛡️  تعديل مباشر"))
        
        self.after(200, self.fade_in)
        self.source_path = ""; self.locked_file = ""; self.key_file = ""; self.operation_result = None; self.live_edit_temp_path = None; self.session_window = None

    def setup_encrypt_decrypt_ui(self, tab, mode):
        tab.grid_columnconfigure(0, weight=1)
        if mode == "encrypt":
            title = ctk.CTkLabel(tab, text="تأمين ملف أو مجلد", font=ctk.CTkFont(size=22, weight="bold"))
            path_button = ctk.CTkButton(tab, text="📂  اختر...", fg_color=THEME_COLOR, hover_color="#14B8A6", command=self.select_path_to_encrypt)
            self.path_label_enc = ctk.CTkLabel(tab, text="لم يتم اختيار أي شيء", text_color="gray", anchor="w")
            password_entry = ctk.CTkEntry(tab, placeholder_text="أدخل كلمة مرور قوية جدًا", show="*", height=40)
            use_keyfile_check = ctk.CTkCheckBox(tab, text="أمان إضافي (مُوصى به): كلمة مرور + ملف مفتاح", font=ctk.CTkFont(weight="bold"), fg_color=THEME_COLOR)
            use_keyfile_check.select()
            action_button = ctk.CTkButton(tab, text="🔒  تشفير", height=50, font=ctk.CTkFont(size=20, weight="bold"), command=self.start_encryption_thread)
            title.grid(row=0, column=0, padx=30, pady=20); path_button.grid(row=1, column=0, padx=30, pady=10, sticky="w"); self.path_label_enc.grid(row=2, column=0, padx=30, pady=5, sticky="ew")
            password_entry.grid(row=3, column=0, padx=30, pady=20, sticky="ew"); use_keyfile_check.grid(row=4, column=0, padx=30, pady=10, sticky="w")
            action_button.grid(row=5, column=0, padx=30, pady=(30, 20), sticky="ew")
            self.password_entry_enc = password_entry; self.use_keyfile_check = use_keyfile_check; self.encrypt_button = action_button
        else: # decrypt
            title = ctk.CTkLabel(tab, text="فك تشفير ملف", font=ctk.CTkFont(size=22, weight="bold"))
            select_file_button = ctk.CTkButton(tab, text="📂  اختر الملف المشفر...", fg_color=THEME_COLOR, hover_color="#14B8A6", command=self.select_file_to_decrypt)
            self.locked_file_label_dec = ctk.CTkLabel(tab, text="...", text_color="gray")
            select_key_button = ctk.CTkButton(tab, text="🔑  اختر ملف المفتاح...", fg_color=THEME_COLOR, hover_color="#14B8A6", command=self.select_key_file)
            self.key_file_label_dec = ctk.CTkLabel(tab, text="...", text_color="gray")
            password_entry = ctk.CTkEntry(tab, placeholder_text="أدخل كلمة المرور", show="*", height=40)
            action_button = ctk.CTkButton(tab, text="🔑  فك التشفير", height=50, font=ctk.CTkFont(size=20, weight="bold"), command=self.start_decryption_thread)
            title.grid(row=0, column=0, padx=30, pady=20); select_file_button.grid(row=1, column=0, padx=30, pady=(10, 5), sticky="ew"); self.locked_file_label_dec.grid(row=2, column=0, padx=30, pady=(0, 15), sticky="w")
            select_key_button.grid(row=3, column=0, padx=30, pady=(10, 5), sticky="ew"); self.key_file_label_dec.grid(row=4, column=0, padx=30, pady=(0, 15), sticky="w")
            password_entry.grid(row=5, column=0, padx=30, pady=15, sticky="ew"); action_button.grid(row=6, column=0, padx=30, pady=(20, 15), sticky="ew")
            self.password_entry_dec = password_entry; self.select_key_button_dec = select_key_button; self.decrypt_button = action_button

    def setup_live_edit_ui(self, tab):
        tab.grid_columnconfigure(0, weight=1)
        title = ctk.CTkLabel(tab, text="التعديل المباشر والآمن", font=ctk.CTkFont(size=22, weight="bold"))
        select_file_button = ctk.CTkButton(tab, text="📂  اختر الملف المشفر للتعديل...", command=self.select_file_for_live_edit)
        self.live_edit_file_label = ctk.CTkLabel(tab, text="...", text_color="gray")
        select_key_button = ctk.CTkButton(tab, text="🔑  اختر ملف المفتاح (إن وجد)...", command=self.select_key_file_for_live_edit)
        self.live_edit_key_label = ctk.CTkLabel(tab, text="...", text_color="gray")
        password_entry = ctk.CTkEntry(tab, placeholder_text="أدخل كلمة المرور لفتح الجلسة", show="*", height=40)
        action_button = ctk.CTkButton(tab, text="🛡️  فتح وبدء التعديل", height=50, font=ctk.CTkFont(size=20, weight="bold"), command=self.start_live_edit_thread)
        
        title.grid(row=0, column=0, padx=30, pady=20); select_file_button.grid(row=1, column=0, padx=30, pady=(10, 5), sticky="ew"); self.live_edit_file_label.grid(row=2, column=0, padx=30, pady=(0, 15), sticky="w")
        select_key_button.grid(row=3, column=0, padx=30, pady=(10, 5), sticky="ew"); self.live_edit_key_label.grid(row=4, column=0, padx=30, pady=(0, 15), sticky="w")
        password_entry.grid(row=5, column=0, padx=30, pady=15, sticky="ew"); action_button.grid(row=6, column=0, padx=30, pady=(20, 15), sticky="ew")
        
        self.password_entry_live = password_entry; self.select_key_button_live = select_key_button; self.live_edit_button = action_button

    # --- دوال الواجهة والتحكم ---
    def resource_path(self, relative_path):
        try: base_path = sys._MEIPASS
        except Exception: base_path = os.path.abspath(".")
        return os.path.join(base_path, relative_path)
    def fade_in(self):
        alpha = self.attributes('-alpha')
        if alpha < 1: alpha += 0.08; self.attributes('-alpha', alpha); self.after(15, self.fade_in)
    def update_status(self, text): self.status_label.configure(text=text)
    def toggle_ui_state(self, state="disabled"):
        buttons = [self.encrypt_button, self.decrypt_button, self.live_edit_button]
        for btn in buttons: btn.configure(state=state)
        self.tabview.configure(state=state)
        if state == "disabled": self.progress_bar.grid(row=6, column=0, padx=20, pady=10, sticky="sew"); self.progress_bar.
