import tkinter as tk
from tkinter import ttk, messagebox, font
import json
import os

class TodoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("قائمة المهام المطورة")
        self.root.geometry("500x550")
        self.root.configure(bg="#f0f0f0")

        # --- إعداد الخطوط والأنماط ---
        self.default_font = font.Font(family="Segoe UI", size=11)
        self.strikethrough_font = font.Font(family="Segoe UI", size=11, overstrike=True)
        
        # إعداد نمط ttk
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure("TButton", font=self.default_font, padding=5)
        style.configure("TEntry", padding=5)
        style.configure("TLabel", background="#f0f0f0", font=("Segoe UI", 16, "bold"))
        style.configure("Treeview", rowheight=30, font=self.default_font)
        style.map("Treeview", background=[("selected", "#0078d7")])

        self.tasks = []
        self.load_tasks()

        # --- واجهة المستخدم ---
        main_frame = ttk.Frame(root, padding="10 10 10 10")
        main_frame.pack(fill="both", expand=True)

        title_label = ttk.Label(main_frame, text="قائمة المهام اليومية")
        title_label.pack(pady=(0, 10))
        
        # --- قائمة المهام (باستخدام Treeview) ---
        self.task_tree = ttk.Treeview(main_frame, columns=("task"), show="headings", selectmode="browse")
        self.task_tree.heading("task", text="المهمة")
        self.task_tree.pack(fill="both", expand=True)
        
        # ربط حدث الضغط المزدوج
        self.task_tree.bind("<Double-1>", self.toggle_task_completion_event)

        # --- حقل الإدخال ---
        entry_frame = ttk.Frame(main_frame)
        entry_frame.pack(pady=10, fill="x")

        self.task_entry = ttk.Entry(entry_frame, font=self.default_font)
        self.task_entry.pack(side="left", fill="x", expand=True)
        self.task_entry.bind("<Return>", self.add_task_event)

        add_button = ttk.Button(entry_frame, text="➕ إضافة", command=self.add_task, style="Accent.TButton")
        add_button.pack(side="right", padx=(5, 0))
        style.configure("Accent.TButton", background="#0078d7", foreground="white")
        style.map("Accent.TButton", background=[("active", "#005a9e")])

        # --- أزرار التحكم ---
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(pady=10, fill="x", side="bottom")

        complete_button = ttk.Button(button_frame, text="✅ إتمام", command=self.mark_task_complete)
        complete_button.pack(side="right", padx=5)
        
        delete_button = ttk.Button(button_frame, text="❌ حذف", command=self.delete_task)
        delete_button.pack(side="right", padx=5)

        clear_button = ttk.Button(button_frame, text="🧹 حذف المكتمل", command=self.clear_completed_tasks)
        clear_button.pack(side="right")
        
        self.populate_tasks()
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def get_selected_task_id(self):
        selected_item = self.task_tree.focus()
        return selected_item

    def add_task(self):
        task_text = self.task_entry.get().strip()
        if task_text:
            self.tasks.append({"text": task_text, "completed": False})
            self.populate_tasks()
            self.task_entry.delete(0, tk.END)
        else:
            messagebox.showwarning("مهمة فارغة", "الرجاء إدخال نص للمهمة.")
    
    def add_task_event(self, event):
        self.add_task()

    def delete_task(self):
        task_id = self.get_selected_task_id()
        if not task_id:
            messagebox.showwarning("لم يتم التحديد", "الرجاء تحديد مهمة لحذفها.")
            return

        if messagebox.askyesno("تأكيد الحذف", "هل أنت متأكد من رغبتك في حذف هذه المهمة؟"):
            index = self.task_tree.index(task_id)
            self.tasks.pop(index)
            self.populate_tasks()

    def mark_task_complete(self):
        task_id = self.get_selected_task_id()
        if not task_id:
            messagebox.showwarning("لم يتم التحديد", "الرجاء تحديد مهمة لإتمامها.")
            return
        
        index = self.task_tree.index(task_id)
        self.tasks[index]["completed"] = not self.tasks[index]["completed"]
        self.populate_tasks()

    def toggle_task_completion_event(self, event):
        self.mark_task_complete()
        
    def clear_completed_tasks(self):
        if messagebox.askyesno("تأكيد", "هل أنت متأكد من حذف جميع المهام المكتملة؟"):
            self.tasks = [task for task in self.tasks if not task["completed"]]
            self.populate_tasks()

    def populate_tasks(self):
        for i in self.task_tree.get_children():
            self.task_tree.delete(i)
        
        # إعداد التاجات للألوان والخطوط
        self.task_tree.tag_configure("completed", foreground="gray", font=self.strikethrough_font)
        self.task_tree.tag_configure("pending", font=self.default_font)

        for i, task in enumerate(self.tasks):
            tag = "completed" if task["completed"] else "pending"
            self.task_tree.insert("", "end", iid=i, values=(task["text"],), tags=(tag,))

    def save_tasks(self):
        with open("tasks.json", "w", encoding="utf-8") as f:
            json.dump(self.tasks, f, ensure_ascii=False, indent=4)

    def load_tasks(self):
        if os.path.exists("tasks.json"):
            try:
                with open("tasks.json", "r", encoding="utf-8") as f:
                    self.tasks = json.load(f)
            except (json.JSONDecodeError, FileNotFoundError):
                self.tasks = []
        else:
            self.tasks = []

    def on_closing(self):
        self.save_tasks()
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = TodoApp(root)
    root.mainloop()
