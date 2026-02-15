import tkinter as tk
from tkinter import messagebox
import json

class TodoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("قائمة المهام")
        self.root.geometry("400x500")
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        self.tasks = []
        self.load_tasks()

        # --- واجهة المستخدم ---
        # الإطار الرئيسي
        main_frame = tk.Frame(root)
        main_frame.pack(pady=10, padx=10, fill="both", expand=True)

        # عنوان
        title_label = tk.Label(main_frame, text="قائمة المهام اليومية", font=("Helvetica", 16, "bold"))
        title_label.pack(pady=5)

        # قائمة المهام
        self.task_listbox = tk.Listbox(main_frame, height=15, bd=0, font=("Helvetica", 12))
        self.task_listbox.pack(fill="both", expand=True)
        self.populate_tasks()

        # حقل إدخال المهام
        self.task_entry = tk.Entry(main_frame, font=("Helvetica", 12))
        self.task_entry.pack(pady=10, fill="x")

        # أزرار التحكم
        button_frame = tk.Frame(main_frame)
        button_frame.pack(pady=5)

        add_button = tk.Button(button_frame, text="إضافة مهمة", command=self.add_task, bg="#4CAF50", fg="white", font=("Helvetica", 10))
        add_button.pack(side="left", padx=5)

        delete_button = tk.Button(button_frame, text="حذف المهمة", command=self.delete_task, bg="#f44336", fg="white", font=("Helvetica", 10))
        delete_button.pack(side="left", padx=5)

    def add_task(self):
        task = self.task_entry.get()
        if task:
            self.tasks.append(task)
            self.populate_tasks()
            self.task_entry.delete(0, tk.END)
        else:
            messagebox.showwarning("تحذير", "لا يمكن إضافة مهمة فارغة.")

    def delete_task(self):
        try:
            selected_task_index = self.task_listbox.curselection()[0]
            self.tasks.pop(selected_task_index)
            self.populate_tasks()
        except IndexError:
            messagebox.showwarning("تحذير", "الرجاء تحديد مهمة لحذفها.")

    def populate_tasks(self):
        self.task_listbox.delete(0, tk.END)
        for task in self.tasks:
            self.task_listbox.insert(tk.END, task)

    def save_tasks(self):
        with open("tasks.json", "w") as f:
            json.dump(self.tasks, f)

    def load_tasks(self):
        try:
            with open("tasks.json", "r") as f:
                self.tasks = json.load(f)
        except FileNotFoundError:
            self.tasks = []

    def on_closing(self):
        self.save_tasks()
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = TodoApp(root)
    root.mainloop()
