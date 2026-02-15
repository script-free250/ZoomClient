import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, font
import json
import os
from datetime import datetime
from tkcalendar import DateEntry

# --- إعدادات الألوان للتصميم الداكن ---
BG_COLOR = "#282c34"
FG_COLOR = "#abb2bf"
CANVAS_COLOR = "#21252b"
TEXT_COLOR = "#ffffff"
COMPLETED_COLOR = "#6c757d"
SELECT_BG = "#3a3f4b"
BUTTON_COLOR = "#404552"
ACCENT_COLOR = "#61afef"

# --- إعدادات الأولويات ---
PRIORITIES = {"عالية": "#e06c75", "متوسطة": "#e5c07b", "منخفضة": "#98c379", "لا يوجد": FG_COLOR}

class PowerTodoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Power To-Do List")
        self.root.geometry("900x700")
        self.root.configure(bg=BG_COLOR)
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        # --- تحميل الخطوط ---
        self.default_font = font.Font(family="Segoe UI", size=10)
        self.strikethrough_font = font.Font(family="Segoe UI", size=10, overstrike=True)

        # --- إعداد الأنماط ---
        self.setup_styles()

        self.tasks = []
        self.load_tasks()

        # --- الإطارات الرئيسية ---
        self.left_frame = ttk.Frame(root)
        self.left_frame.pack(side="left", fill="both", expand=True, padx=10, pady=10)

        self.right_frame = ttk.Frame(root, width=300)
        self.right_frame.pack(side="right", fill="y", padx=(0, 10), pady=10)
        self.right_frame.pack_propagate(False)

        # --- مكونات الإطار الأيسر ---
        self.create_left_widgets()

        # --- مكونات الإطار الأيمن ---
        self.create_right_widgets()
        
        # --- قائمة السياق (Right-click menu) ---
        self.create_context_menu()

        self.populate_tree()
        self.update_stats()
        self.update_details_pane(None)

    def setup_styles(self):
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure(".", background=BG_COLOR, foreground=FG_COLOR, fieldbackground=CANVAS_COLOR, bordercolor="#828282")
        style.configure("TLabel", font=("Segoe UI", 10))
        style.configure("TButton", font=("Segoe UI", 10, "bold"), background=BUTTON_COLOR, foreground=TEXT_COLOR)
        style.map("TButton", background=[("active", ACCENT_COLOR)])
        style.configure("Treeview", rowheight=28, font=self.default_font, background=CANVAS_COLOR)
        style.map("Treeview", background=[("selected", SELECT_BG)], foreground=[("selected", TEXT_COLOR)])
        style.configure("Treeview.Heading", font=("Segoe UI", 11, "bold"), background=BG_COLOR, foreground=ACCENT_COLOR)
        style.layout("Treeview", [('Treeview.treearea', {'sticky': 'nswe'})]) # Hide borders

    def create_left_widgets(self):
        # --- شريط الإدخال والبحث ---
        input_frame = ttk.Frame(self.left_frame)
        input_frame.pack(fill="x", pady=(0, 5))

        self.task_entry = ttk.Entry(input_frame, font=("Segoe UI", 12))
        self.task_entry.pack(fill="x", expand=True, side="left", padx=(0, 5))
        self.task_entry.bind("<Return>", lambda e: self.add_task())
        
        add_button = ttk.Button(input_frame, text="➕", width=3, command=self.add_task)
        add_button.pack(side="left")

        self.search_entry = ttk.Entry(input_frame, font=("Segoe UI", 10), width=20)
        self.search_entry.pack(side="right", padx=(5,0))
        self.search_entry.insert(0, "🔍 ابحث...")
        self.search_entry.bind("<FocusIn>", lambda e: self.search_entry.delete(0, 'end'))
        self.search_entry.bind("<KeyRelease>", self.filter_tasks)

        # --- شجرة المهام ---
        tree_frame = ttk.Frame(self.left_frame)
        tree_frame.pack(fill="both", expand=True)

        self.task_tree = ttk.Treeview(tree_frame, columns=("priority", "due_date", "task"), show="headings")
        self.task_tree.heading("priority", text="!")
        self.task_tree.heading("due_date", text="تاريخ الاستحقاق")
        self.task_tree.heading("task", text="المهمة")
        self.task_tree.column("priority", width=30, anchor="center")
        self.task_tree.column("due_date", width=120, anchor="center")
        self.task_tree.column("task", width=400)
        
        self.task_tree.pack(fill="both", expand=True)
        self.task_tree.bind("<<TreeviewSelect>>", self.update_details_pane)
        self.task_tree.bind("<Button-3>", self.show_context_menu)

        # --- شريط الحالة ---
        status_frame = ttk.Frame(self.left_frame)
        status_frame.pack(fill="x", pady=(5,0))
        self.progress_bar = ttk.Progressbar(status_frame, orient="horizontal", mode="determinate")
        self.progress_bar.pack(fill="x", expand=True, side="left", padx=(0,10))
        self.stats_label = ttk.Label(status_frame, text="الإحصائيات: 0/0")
        self.stats_label.pack(side="right")

    def create_right_widgets(self):
        # --- قسم التفاصيل ---
        details_label = ttk.Label(self.right_frame, text="تفاصيل المهمة", font=("Segoe UI", 14, "bold"), foreground=ACCENT_COLOR)
        details_label.pack(pady=10)

        self.details_task_label = ttk.Label(self.right_frame, text="", wraplength=280, font=("Segoe UI", 12))
        self.details_task_label.pack(pady=5, fill="x")

        # --- تاريخ الاستحقاق ---
        ttk.Label(self.right_frame, text="تاريخ الاستحقاق:", font=("Segoe UI", 10, "bold")).pack(pady=(10,0))
        self.details_date_entry = DateEntry(self.right_frame, width=12, background=ACCENT_COLOR,
            foreground='white', borderwidth=2, date_pattern='yyyy-mm-dd', state='disabled')
        self.details_date_entry.pack(pady=5)
        self.details_date_entry.bind("<<DateEntrySelected>>", self.update_due_date)

        # --- الأولوية ---
        ttk.Label(self.right_frame, text="الأولوية:", font=("Segoe UI", 10, "bold")).pack(pady=(10,0))
        self.priority_var = tk.StringVar()
        priority_menu = ttk.OptionMenu(self.right_frame, self.priority_var, "لا يوجد", *PRIORITIES.keys(), command=self.update_priority)
        priority_menu.pack(pady=5, fill="x")

        # --- قسم الملاحظات ---
        ttk.Label(self.right_frame, text="الملاحظات:", font=("Segoe UI", 10, "bold")).pack(pady=(10,0))
        self.notes_text = tk.Text(self.right_frame, height=10, bg=CANVAS_COLOR, fg=TEXT_COLOR, insertbackground=TEXT_COLOR, font=self.default_font, relief="flat")
        self.notes_text.pack(pady=5, fill="both", expand=True)
        self.notes_text.bind("<KeyRelease>", self.update_notes)

        # --- الإجراءات ---
        actions_frame = ttk.Frame(self.right_frame)
        actions_frame.pack(fill="x", pady=10)
        ttk.Button(actions_frame, text="📝 تعديل", command=self.edit_task).pack(side="left", expand=True)
        ttk.Button(actions_frame, text="✅ إتمام", command=self.toggle_complete).pack(side="left", expand=True)
        
        subtask_button = ttk.Button(self.right_frame, text="➕ إضافة مهمة فرعية", command=self.add_subtask)
        subtask_button.pack(fill="x", pady=5)
        
        # --- الفرز والفلترة ---
        sort_filter_frame = ttk.LabelFrame(self.right_frame, text="تنظيم")
        sort_filter_frame.pack(fill="x", pady=10)
        
        ttk.Button(sort_filter_frame, text="فرز حسب الأولوية", command=lambda: self.sort_tasks("priority")).pack(fill="x")
        ttk.Button(sort_filter_frame, text="فرز حسب التاريخ", command=lambda: self.sort_tasks("due_date")).pack(fill="x", pady=5)
        
        filter_var = tk.StringVar(value="الكل")
        ttk.Radiobutton(sort_filter_frame, text="الكل", variable=filter_var, value="الكل", command=self.filter_tasks).pack(anchor="w")
        ttk.Radiobutton(sort_filter_frame, text="قيد الإنجاز", variable=filter_var, value="قيد الإنجاز", command=self.filter_tasks).pack(anchor="w")
        ttk.Radiobutton(sort_filter_frame, text="مكتملة", variable=filter_var, value="مكتملة", command=self.filter_tasks).pack(anchor="w")
        self.filter_var = filter_var

        # --- خيارات إضافية ---
        self.always_on_top_var = tk.BooleanVar()
        ttk.Checkbutton(self.right_frame, text="البقاء في الأعلى", variable=self.always_on_top_var, command=self.toggle_always_on_top).pack(pady=10)

    def create_context_menu(self):
        self.context_menu = tk.Menu(self.root, tearoff=0, bg=CANVAS_COLOR, fg=FG_COLOR)
        self.context_menu.add_command(label="📝 تعديل", command=self.edit_task)
        self.context_menu.add_command(label="🗑️ حذف", command=self.delete_task)
        self.context_menu.add_separator()
        priority_submenu = tk.Menu(self.context_menu, tearoff=0, bg=CANVAS_COLOR, fg=FG_COLOR)
        self.context_menu.add_cascade(label="⭐ تحديد الأولوية", menu=priority_submenu)
        for p in PRIORITIES:
            priority_submenu.add_command(label=p, command=lambda pr=p: self.set_priority_from_menu(pr))
            
    def show_context_menu(self, event):
        item_id = self.task_tree.identify_row(event.y)
        if item_id:
            self.task_tree.selection_set(item_id)
            self.context_menu.post(event.x_root, event.y_root)

    # --- دوال العمليات ---
    
    def find_task_by_id(self, task_id, tasks_list=None):
        if tasks_list is None:
            tasks_list = self.tasks
        for task in tasks_list:
            if task['id'] == task_id:
                return task
            if 'subtasks' in task:
                found = self.find_task_by_id(task_id, task['subtasks'])
                if found:
                    return found
        return None

    def get_selected_task(self):
        selected_id = self.get_selected_task_id()
        if selected_id:
            return self.find_task_by_id(selected_id)
        return None

    def get_selected_task_id(self):
        selection = self.task_tree.selection()
        return selection[0] if selection else None

    def add_task(self, parent_id=None):
        task_text = self.task_entry.get().strip()
        if not task_text: return
        
        new_task = {
            "id": self.generate_task_id(),
            "text": task_text,
            "completed": False,
            "due_date": None,
            "priority": "لا يوجد",
            "notes": "",
            "subtasks": []
        }

        if parent_id:
            parent_task = self.find_task_by_id(parent_id)
            if parent_task:
                parent_task['subtasks'].append(new_task)
        else:
            self.tasks.append(new_task)

        self.task_entry.delete(0, 'end')
        self.populate_tree()
        self.update_stats()

    def add_subtask(self):
        parent_id = self.get_selected_task_id()
        if not parent_id:
            messagebox.showwarning("خطأ", "الرجاء تحديد مهمة رئيسية أولاً.")
            return
        self.add_task(parent_id=parent_id)

    def edit_task(self):
        task = self.get_selected_task()
        if not task: return
        
        new_text = simpledialog.askstring("تعديل المهمة", "قم بتعديل نص المهمة:", initialvalue=task['text'], parent=self.root)
        if new_text and new_text.strip():
            task['text'] = new_text.strip()
            self.populate_tree()
            self.update_details_pane(None)
            
    def delete_task(self):
        selected_id = self.get_selected_task_id()
        if not selected_id: return
        
        if messagebox.askyesno("تأكيد الحذف", "هل أنت متأكد من حذف هذه المهمة وجميع مهامها الفرعية؟"):
            def remove_task(tasks_list, task_id):
                for i, task in enumerate(tasks_list):
                    if task['id'] == task_id:
                        tasks_list.pop(i)
                        return True
                    if 'subtasks' in task:
                        if remove_task(task['subtasks'], task_id):
                            return True
                return False
            
            remove_task(self.tasks, selected_id)
            self.populate_tree()
            self.update_stats()
            self.update_details_pane(None)

    def toggle_complete(self):
        task = self.get_selected_task()
        if not task: return
        task['completed'] = not task['completed']
        self.populate_tree()
        self.update_stats()
        self.update_details_pane(None)

    def sort_tasks(self, by):
        if by == "priority":
            priority_order = {"عالية": 0, "متوسطة": 1, "منخفضة": 2, "لا يوجد": 3}
            self.tasks.sort(key=lambda t: priority_order[t['priority']])
        elif by == "due_date":
            self.tasks.sort(key=lambda t: datetime.strptime(t['due_date'], "%Y-%m-%d") if t['due_date'] else datetime.max)
        self.populate_tree()

    def filter_tasks(self, event=None):
        self.populate_tree()

    def toggle_always_on_top(self):
        self.root.attributes("-topmost", self.always_on_top_var.get())

    # --- دوال التحديث ---

    def populate_tree(self):
        for item in self.task_tree.get_children():
            self.task_tree.delete(item)

        filter_mode = self.filter_var.get()
        search_query = self.search_entry.get().lower()
        if search_query == "🔍 ابحث...":
            search_query = ""

        def insert_task(task, parent=""):
            # تطبيق الفلتر
            if filter_mode == "مكتملة" and not task['completed']: return False
            if filter_mode == "قيد الإنجاز" and task['completed']: return False
            
            # تطبيق البحث
            show_task = search_query in task['text'].lower()
            
            has_visible_subtask = False
            if 'subtasks' in task and task['subtasks']:
                for sub in task['subtasks']:
                    if insert_task(sub, parent=task['id']):
                        has_visible_subtask = True
            
            if not show_task and not has_visible_subtask:
                return False

            # إدراج المهمة
            tag = "completed" if task['completed'] else "pending"
            priority_icon = "★"
            self.task_tree.tag_configure(task['id'], foreground=PRIORITIES[task['priority']])

            self.task_tree.insert(parent, "end", iid=task['id'], values=(priority_icon, task.get('due_date') or "‐", task['text']), tags=(tag, task['id']))
            return True

        for task in self.tasks:
            insert_task(task)

        # تطبيق الخطوط
        self.task_tree.tag_configure("completed", font=self.strikethrough_font, foreground=COMPLETED_COLOR)
        self.task_tree.tag_configure("pending", font=self.default_font)

    def update_details_pane(self, event):
        task = self.get_selected_task()
        if task:
            self.details_task_label.config(text=task['text'])
            self.details_date_entry.config(state='normal')
            if task['due_date']:
                self.details_date_entry.set_date(datetime.strptime(task['due_date'], "%Y-%m-%d"))
            else:
                self.details_date_entry.set_date(None)
            
            self.priority_var.set(task['priority'])
            self.notes_text.config(state="normal")
            self.notes_text.delete(1.0, "end")
            self.notes_text.insert(1.0, task.get('notes', ''))
        else:
            self.details_task_label.config(text="الرجاء تحديد مهمة")
            self.details_date_entry.set_date(None)
            self.details_date_entry.config(state='disabled')
            self.priority_var.set("لا يوجد")
            self.notes_text.delete(1.0, "end")
            self.notes_text.config(state="disabled")

    def update_due_date(self, event):
        task = self.get_selected_task()
        if not task: return
        task['due_date'] = self.details_date_entry.get_date().strftime("%Y-%m-%d")
        self.populate_tree()

    def update_priority(self, new_priority):
        task = self.get_selected_task()
        if not task: return
        task['priority'] = new_priority
        self.populate_tree()

    def set_priority_from_menu(self, priority):
        self.priority_var.set(priority)
        self.update_priority(priority)
        
    def update_notes(self, event=None):
        task = self.get_selected_task()
        if not task: return
        task['notes'] = self.notes_text.get(1.0, "end-1c")

    def update_stats(self):
        total_tasks = 0
        completed_tasks = 0
        def count_tasks(tasks_list):
            nonlocal total_tasks, completed_tasks
            for task in tasks_list:
                total_tasks += 1
                if task['completed']:
                    completed_tasks += 1
                if 'subtasks' in task:
                    count_tasks(task['subtasks'])
        
        count_tasks(self.tasks)
        
        self.stats_label.config(text=f"الإحصائيات: {completed_tasks}/{total_tasks}")
        if total_tasks > 0:
            self.progress_bar['value'] = (completed_tasks / total_tasks) * 100
        else:
            self.progress_bar['value'] = 0

    # --- الحفظ والتحميل ---
    
    def generate_task_id(self):
        return str(datetime.now().timestamp()).replace(".", "")

    def on_closing(self):
        self.save_tasks()
        self.root.destroy()

    def save_tasks(self):
        with open("tasks_data.json", "w", encoding="utf-8") as f:
            json.dump(self.tasks, f, ensure_ascii=False, indent=4)

    def load_tasks(self):
        if os.path.exists("tasks_data.json"):
            try:
                with open("tasks_data.json", "r", encoding="utf-8") as f:
                    self.tasks = json.load(f)
            except (json.JSONDecodeError, FileNotFoundError):
                self.tasks = []
        else:
            self.tasks = []


if __name__ == "__main__":
    root = tk.Tk()
    app = PowerTodoApp(root)
    root.mainloop()

