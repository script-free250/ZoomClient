import customtkinter as ctk
import tkinter as tk
from tkinter import messagebox

class TodoApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("مدير المهام اليومية")
        self.geometry("700x500")

        ctk.set_appearance_mode("System")  # Modes: "System" (default), "Dark", "Light"
        ctk.set_default_color_theme("blue")  # Themes: "blue" (default), "green", "dark-blue"

        # --- Frames ---
        self.main_frame = ctk.CTkFrame(self, corner_radius=15)
        self.main_frame.pack(pady=20, padx=20, fill="both", expand=True)

        # --- Widgets ---
        self.label = ctk.CTkLabel(self.main_frame, text="أضف مهمة جديدة:", font=ctk.CTkFont(size=20, weight="bold"))
        self.label.pack(pady=(10, 5))

        self.entry = ctk.CTkEntry(self.main_frame, placeholder_text="اكتب مهمتك هنا...", width=300, font=ctk.CTkFont(size=14))
        self.entry.pack(pady=10)
        self.entry.bind("<Return>", self.add_task)

        self.add_button = ctk.CTkButton(self.main_frame, text="إضافة مهمة", command=self.add_task, font=ctk.CTkFont(size=14, weight="bold"))
        self.add_button.pack(pady=10)

        self.tasks_frame = ctk.CTkScrollableFrame(self.main_frame, label_text="قائمة المهام")
        self.tasks_frame.pack(pady=10, padx=20, fill="both", expand=True)

        self.task_list = []

    def add_task(self, event=None):
        task_text = self.entry.get()
        if task_text:
            task_frame = ctk.CTkFrame(self.tasks_frame, corner_radius=10)
            task_frame.pack(fill="x", pady=5, padx=5)

            task_label = ctk.CTkLabel(task_frame, text=task_text, font=ctk.CTkFont(size=16))
            task_label.pack(side="left", padx=10)

            delete_button = ctk.CTkButton(task_frame, text="حذف", width=60, fg_color="transparent", border_width=2,
                                          text_color=("gray10", "#DCE4EE"), command=lambda f=task_frame: self.delete_task(f))
            delete_button.pack(side="right", padx=10)

            complete_button = ctk.CTkButton(task_frame, text="إنجاز", width=60, command=lambda lbl=task_label: self.mark_as_done(lbl))
            complete_button.pack(side="right", padx=(0, 5))


            self.task_list.append(task_frame)
            self.entry.delete(0, "end")
        else:
            messagebox.showwarning("تحذير", "لا يمكن إضافة مهمة فارغة.")

    def delete_task(self, frame):
        frame.destroy()
        self.task_list.remove(frame)

    def mark_as_done(self, label):
        current_text = label.cget("text")
        # Add a strikethrough effect
        label.configure(font=ctk.CTkFont(size=16, slant="italic", overstrike=True))


if __name__ == "__main__":
    app = TodoApp()
    app.mainloop()

