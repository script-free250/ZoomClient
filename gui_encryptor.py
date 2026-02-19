import os
import base64
import customtkinter as ctk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# --- نفس دوال التشفير الأساسية من قبل ---
def generate_key_from_password(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

# --- الفئة الرئيسية للبرنامج ---
class App(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("برنامج تشفير الملفات")
        self.geometry("500x300")
        self.selected_file_path = None

        # إعدادات المظهر
        ctk.set_appearance_mode("System")  # يمكن تغييره إلى "Dark" أو "Light"
        ctk.set_default_color_theme("blue")

        # --- عناصر الواجهة ---
        
        # 1. زر اختيار الملف
        self.select_file_button = ctk.CTkButton(self, text="اختر ملفًا", command=self.select_file)
        self.select_file_button.pack(pady=20, padx=20)

        # 2. ليبل لعرض اسم الملف المختار
        self.file_label = ctk.CTkLabel(self, text="لم يتم اختيار أي ملف", text_color="gray")
        self.file_label.pack(pady=5, padx=20)

        # 3. حقل إدخال كلمة المرور
        self.password_entry = ctk.CTkEntry(self, placeholder_text="أدخل كلمة المرور هنا", show="*")
        self.password_entry.pack(pady=10, padx=20)

        # 4. إطار لأزرار التشفير وفك التشفير
        self.button_frame = ctk.CTkFrame(self)
        self.button_frame.pack(pady=10)

        self.encrypt_button = ctk.CTkButton(self.button_frame, text="تشفير", command=self.encrypt_file_action)
        self.encrypt_button.pack(side="left", padx=10)

        self.decrypt_button = ctk.CTkButton(self.button_frame, text="فك التشفير", command=self.decrypt_file_action)
        self.decrypt_button.pack(side="left", padx=10)

    def select_file(self):
        """يفتح نافذة لاختيار ملف ويحفظ مساره."""
        file_path = filedialog.askopenfilename()
        if file_path:
            self.selected_file_path = file_path
            self.file_label.configure(text=os.path.basename(file_path), text_color="white")

    def process_file(self, mode: str):
        """الدالة الأساسية لمعالجة الملف (تشفير أو فك تشفير)."""
        if not self.selected_file_path:
            messagebox.showerror("خطأ", "الرجاء اختيار ملف أولاً.")
            return

        password = self.password_entry.get()
        if not password:
            messagebox.showerror("خطأ", "الرجاء إدخال كلمة المرور.")
            return

        try:
            if mode == "encrypt":
                # قراءة الملف الأصلي
                with open(self.selected_file_path, 'rb') as f:
                    data = f.read()
                
                # توليد مفتاح وتشفير
                salt = os.urandom(16)
                key = generate_key_from_password(password, salt)
                fernet = Fernet(key)
                encrypted_data = fernet.encrypt(data)

                # حفظ الملف المشفر
                encrypted_file_path = self.selected_file_path + ".encrypted"
                with open(encrypted_file_path, 'wb') as f:
                    f.write(salt)
                    f.write(encrypted_data)
                
                messagebox.showinfo("نجاح", f"✅ تم تشفير الملف بنجاح!\nتم الحفظ في: {encrypted_file_path}")

            elif mode == "decrypt":
                # قراءة الملف المشفر
                with open(self.selected_file_path, 'rb') as f:
                    salt = f.read(16)
                    encrypted_data = f.read()

                # توليد مفتاح وفك تشفير
                key = generate_key_from_password(password, salt)
                fernet = Fernet(key)
                decrypted_data = fernet.decrypt(encrypted_data)

                # حفظ الملف الأصلي
                decrypted_file_path = self.selected_file_path.replace(".encrypted", "")
                with open(decrypted_file_path, 'wb') as f:
                    f.write(decrypted_data)

                messagebox.showinfo("نجاح", f"✅ تم فك تشفير الملف بنجاح!\nتم الحفظ في: {decrypted_file_path}")

        except FileNotFoundError:
            messagebox.showerror("خطأ", "لم يتم العثور على الملف المحدد.")
        except Exception as e:
            # هذا الخطأ يظهر غالبًا عند استخدام كلمة مرور خاطئة لفك التشفير
            messagebox.showerror("خطأ", "فشلت العملية. تأكد من صحة كلمة المرور أو أن الملف غير تالف.")

    def encrypt_file_action(self):
        self.process_file("encrypt")

    def decrypt_file_action(self):
        self.process_file("decrypt")


if __name__ == "__main__":
    app = App()
    app.mainloop()
