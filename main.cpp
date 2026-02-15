import customtkinter

# Set the appearance mode and default color theme
customtkinter.set_appearance_mode("System")  # Modes: "System" (standard), "Dark", "Light"
customtkinter.set_default_color_theme("blue")  # Themes: "blue" (standard), "green", "dark-blue"

class App(customtkinter.CTk):
    def __init__(self):
        super().__init__()

        # Configure window
        self.title("قائمة المهام اليومية")
        self.geometry("500x450")

        # Configure grid layout
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # === Title Frame ===
        self.title_label = customtkinter.CTkLabel(self, text="قائمة المهام", font=customtkinter.CTkFont(size=20, weight="bold"))
        self.title_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        # === Main Frame (for Entry and Listbox) ===
        self.main_frame = customtkinter.CTkFrame(self)
        self.main_frame.grid(row=1, column=0, padx=20, pady=10, sticky="nsew")
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(1, weight=1)

        # --- Task Entry ---
        self.entry = customtkinter.CTkEntry(self.main_frame, placeholder_text="اكتب مهمة جديدة...")
        self.entry.grid(row=0, column=0, padx=10, pady=(10, 5), sticky="ew")
        self.entry.bind("<Return>", self.add_task_event)


        # --- Tasks Listbox ---
        self.task_listbox = customtkinter.CTkTextbox(self.main_frame, width=400, height=250)
        self.task_listbox.grid(row=1, column=0, padx=10, pady=5, sticky="nsew")


        # === Button Frame ===
        self.button_frame = customtkinter.CTkFrame(self)
        self.button_frame.grid(row=2, column=0, padx=20, pady=(10, 20), sticky="ew")
        self.button_frame.grid_columnconfigure((0, 1), weight=1)

        # --- Add Task Button ---
        self.add_button = customtkinter.CTkButton(self.button_frame, text="إضافة مهمة", command=self.add_task)
        self.add_button.grid(row=0, column=0, padx=10, pady=10, sticky="ew")

        # --- Delete Task Button ---
        self.delete_button = customtkinter.CTkButton(self.button_frame, text="حذف المهمة", fg_color="transparent", border_width=2, command=self.delete_task)
        self.delete_button.grid(row=0, column=1, padx=10, pady=10, sticky="ew")

    def add_task_event(self, event):
        self.add_task()

    def add_task(self):
        task = self.entry.get()
        if task:
            # Add task to the listbox on a new line
            self.task_listbox.insert("end", task + "\n")
            # Clear the entry box
            self.entry.delete(0, "end")

    def delete_task(self):
        try:
            # Get the currently selected line
            selected_task_line = self.task_listbox.get("sel.first linestart", "sel.last lineend")
            if selected_task_line:
                # To delete a line, we need to find its exact start and end index
                # This is a simple approach: get all content and remove the line
                all_content = self.task_listbox.get("1.0", "end")
                new_content = all_content.replace(selected_task_line.strip() + "\n", "")
                self.task_listbox.delete("1.0", "end")
                self.task_listbox.insert("1.0", new_content)
        except Exception as e:
            # This will happen if no text is selected
            print(f"No task selected to delete. Error: {e}")


if __name__ == "__main__":
    app = App()
    app.mainloop()

