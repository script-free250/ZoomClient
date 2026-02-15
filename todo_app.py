import tkinter as tk
from tkinter import font
import json
import os

# --- إعدادات التصميم والألوان ---
BG_COLOR = "#2d2d2d"
ITEM_BG_COLOR = "#3c3c3c"
HOVER_COLOR = "#4a4a4a"
COMPLETED_COLOR = "#222222"
TEXT_COLOR = "#f0f0f0"
COMPLETED_TEXT_COLOR = "#888888"
ACCENT_COLOR = "#00aaff"

class AnimatedTodoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("قائمة المهام الأنيقة")
        self.root.geometry("500x650")
        self.root.configure(bg=BG_COLOR)
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        self.tasks = self.load_tasks()
        self.task_widgets = []

        # --- الخطوط ---
        self.default_font = font.Font(family="Segoe UI", size=12)
        self.strikethrough_font = font.Font(family="Segoe UI", size=12, overstrike=True)

        # --- الواجهة الرئيسية ---
        header_frame = tk.Frame(root, bg=BG_COLOR)
        header_frame.pack(pady=20, padx=20, fill="x")

        self.task_entry = tk.Entry(header_frame, bg=ITEM_BG_COLOR, fg=TEXT_COLOR, 
                                   insertbackground=TEXT_COLOR, font=self.default_font, relief="flat", bd=10)
        self.task_entry.pack(side="left", fill="x", expand=True)
        self.task_entry.bind("<Return>", self.add_task)

        add_button = tk.Button(header_frame, text="➕", bg=ACCENT_COLOR, fg="white", 
                               font=("Segoe UI", 12, "bold"), relief="flat", command=self.add_task, width=3)
        add_button.pack(side="left", padx=(10, 0))

        # --- إطار المهام القابل للتمرير ---
        canvas = tk.Canvas(root, bg=BG_COLOR, highlightthickness=0)
        scrollbar = tk.Scrollbar(root, orient="vertical", command=canvas.yview)
        self.scrollable_frame = tk.Frame(canvas, bg=BG_COLOR)

        self.scrollable_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True, padx=(20, 0))
        scrollbar.pack(side="right", fill="y", padx=(0, 20))
        
        self.root.after(100, self.populate_tasks)

    def populate_tasks(self):
        for task_data in self.tasks:
            self.create_task_widget(task_data)

    def create_task_widget(self, task_data, animate=False):
        task_frame = tk.Frame(self.scrollable_frame, bg=ITEM_BG_COLOR, height=50)
        task_frame.pack(fill="x", pady=(0, 5), padx=5)

        # --- البيانات المرتبطة بالويدجت ---
        task_frame.task_data = task_data
        
        # --- الأدوات داخل إطار المهمة ---
        check_var = tk.BooleanVar(value=task_data["completed"])
        check = tk.Checkbutton(task_frame, variable=check_var, bg=ITEM_BG_COLOR, activebackground=ITEM_BG_COLOR, 
                               relief="flat", command=lambda: self.toggle_complete(task_frame))
        check.pack(side="left", padx=10)

        label = tk.Label(task_frame, text=task_data["text"], bg=ITEM_BG_COLOR, fg=TEXT_COLOR, font=self.default_font, anchor="w")
        label.pack(side="left", fill="x", expand=True)

        delete_button = tk.Button(task_frame, text="❌", bg=ITEM_BG_COLOR, fg=ITEM_BG_COLOR, 
                                  relief="flat", command=lambda: self.delete_task(task_frame))
        delete_button.pack(side="right", padx=10)

        # --- ربط الأحداث ---
        task_frame.bind("<Enter>", lambda e, f=task_frame: self.on_hover(f, True))
        task_frame.bind("<Leave>", lambda e, f=task_frame: self.on_hover(f, False))
        label.bind("<Double-1>", lambda e, f=task_frame: self.edit_task(f))

        # --- تحديث حالة الواجهة ---
        self.update_widget_state(task_frame)
        self.task_widgets.append(task_frame)

        if animate:
            self.animate_fade_in(task_frame)

    def add_task(self, event=None):
        task_text = self.task_entry.get().strip()
        if not task_text:
            return
        
        task_data = {"id": self.generate_id(), "text": task_text, "completed": False}
        self.tasks.append(task_data)
        self.create_task_widget(task_data, animate=True)
        self.task_entry.delete(0, "end")

    def delete_task(self, task_frame):
        self.animate_slide_out(task_frame, on_complete=lambda: self._finalize_delete(task_frame))

    def _finalize_delete(self, task_frame):
        self.tasks.remove(task_frame.task_data)
        self.task_widgets.remove(task_frame)
        task_frame.destroy()
        
    def toggle_complete(self, task_frame):
        task_frame.task_data["completed"] = not task_frame.task_data["completed"]
        self.update_widget_state(task_frame)

    def edit_task(self, task_frame):
        label = [w for w in task_frame.winfo_children() if isinstance(w, tk.Label)][0]
        
        edit_entry = tk.Entry(task_frame, bg=BG_COLOR, fg=TEXT_COLOR, insertbackground=TEXT_COLOR, 
                              font=self.default_font, relief="flat")
        edit_entry.insert(0, task_frame.task_data["text"])
        
        label.pack_forget()
        edit_entry.pack(side="left", fill="x", expand=True)
        edit_entry.focus()
        
        def save_edit(event):
            new_text = edit_entry.get().strip()
            if new_text:
                task_frame.task_data["text"] = new_text
                label.config(text=new_text)
            edit_entry.destroy()
            label.pack(side="left", fill="x", expand=True)

        edit_entry.bind("<Return>", save_edit)
        edit_entry.bind("<FocusOut>", save_edit)

    def update_widget_state(self, task_frame):
        label = [w for w in task_frame.winfo_children() if isinstance(w, tk.Label)][0]
        checkbutton = [w for w in task_frame.winfo_children() if isinstance(w, tk.Checkbutton)][0]
        
        if task_frame.task_data["completed"]:
            label.config(font=self.strikethrough_font, fg=COMPLETED_TEXT_COLOR)
            task_frame.config(bg=COMPLETED_COLOR)
            for child in task_frame.winfo_children():
                child.config(bg=COMPLETED_COLOR)
        else:
            label.config(font=self.default_font, fg=TEXT_COLOR)
            task_frame.config(bg=ITEM_BG_COLOR)
            for child in task_frame.winfo_children():
                child.config(bg=ITEM_BG_COLOR)
        
        # Make sure checkbutton is checked correctly
        check_var = checkbutton.cget('variable')
        checkbutton.setvar(check_var, task_frame.task_data["completed"])

    def on_hover(self, frame, is_hovering):
        delete_button = [w for w in frame.winfo_children() if isinstance(w, tk.Button)][0]
        is_completed = frame.task_data["completed"]
        
        if is_hovering:
            frame.config(bg=COMPLETED_COLOR if is_completed else HOVER_COLOR)
            for child in frame.winfo_children():
                child.config(bg=COMPLETED_COLOR if is_completed else HOVER_COLOR)
            delete_button.config(fg="red")
        else:
            frame.config(bg=COMPLETED_COLOR if is_completed else ITEM_BG_COLOR)
            for child in frame.winfo_children():
                child.config(bg=COMPLETED_COLOR if is_completed else ITEM_BG_COLOR)
            delete_button.config(fg=COMPLETED_COLOR if is_completed else ITEM_BG_COLOR)

    # --- Animations ---
    def animate_fade_in(self, widget, steps=15, interval=15):
        widget.attributes("-alpha", 0.0) # Only works on Toplevel
        # Simulate by expanding height
        widget.pack_forget()
        widget.pack(fill="x", pady=(0, 5), padx=5)
        widget.config(height=1)
        
        def expand(current_height):
            if current_height < 50:
                widget.config(height=current_height + 5)
                self.root.after(interval, lambda: expand(current_height + 5))
            else:
                widget.config(height=50)

        expand(1)

    def animate_slide_out(self, widget, on_complete, steps=20, interval=10):
        width = widget.winfo_width()
        x_pos = 0
        def slide(current_x):
            if current_x < width:
                widget.place(x=current_x, y=widget.winfo_y(), width=width, height=50)
                self.root.after(interval, lambda: slide(current_x + width // steps))
            else:
                widget.place_forget()
                on_complete()

        slide(x_pos)

    # --- Data & Util ---
    def generate_id(self):
        return str(len(self.tasks) + 1) + str(int(os.urandom(1).hex(), 16)))

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
                    return json.load(f)
            except (json.JSONDecodeError, FileNotFoundError):
                return []
        return []

if __name__ == "__main__":
    root = tk.Tk()
    app = AnimatedTodoApp(root)
    root.mainloop()
