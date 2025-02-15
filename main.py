import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import random
import string
import pyperclip
from PIL import Image, ImageTk

class PasswordGeneratorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Password Generator")
        self.root.geometry("600x750")
        self.root.resizable(False, False)
        self.root.configure(bg="#ECF0F1")

        # Header with Image
        self.header_frame = tk.Frame(root, bg="#ECF0F1")
        self.header_frame.pack(fill="x")

        self.logo_img = Image.open("images/password-icon.png")  # Add your own image
        self.logo_img = self.logo_img.resize((75, 75))
        self.logo_photo = ImageTk.PhotoImage(self.logo_img)

        self.logo_label = tk.Label(self.header_frame, image=self.logo_photo, bg="#ECF0F1")
        self.logo_label.pack(side="left", padx=30)

        self.header_label = tk.Label(self.header_frame, text="Advanced Password Generator", font=("Arial", 16, "bold"), bg="#ECF0F1", fg="black")
        self.header_label.pack(side="left", padx=10)

        # Settings Frame
        self.settings_frame = tk.Frame(root, padx=10, pady=10, bg="#ECF0F1")
        self.settings_frame.pack(pady=10, fill="x")

        tk.Label(self.settings_frame, text="Password Length:", font=("Arial", 12), bg="#ECF0F1").grid(row=0, column=0, sticky="w", padx=5)
        self.length_var = tk.IntVar(value=12)
        self.length_spinbox = tk.Spinbox(self.settings_frame, from_=4, to=24, textvariable=self.length_var, width=5)
        self.length_spinbox.grid(row=0, column=1, padx=5)

        tk.Label(self.settings_frame, text="Number of Passwords:", font=("Arial", 12), bg="#ECF0F1").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.num_var = tk.IntVar(value=10)
        self.num_entry = tk.Entry(self.settings_frame, textvariable=self.num_var, width=5)
        self.num_entry.grid(row=1, column=1, padx=5, pady=5)

        # Character Selection
        self.char_frame = tk.LabelFrame(root, text="Character Options", padx=10, pady=10, bg="#ECF0F1")
        self.char_frame.pack(pady=10, fill="x", padx=10)

        self.upper_var = tk.BooleanVar(value=True)
        self.lower_var = tk.BooleanVar(value=True)
        self.digit_var = tk.BooleanVar(value=True)
        self.symbol_var = tk.BooleanVar(value=False)

        tk.Checkbutton(self.char_frame, text="Uppercase", variable=self.upper_var, bg="#ECF0F1").grid(row=0, column=0, sticky="w")
        tk.Checkbutton(self.char_frame, text="Lowercase", variable=self.lower_var, bg="#ECF0F1").grid(row=0, column=1, sticky="w")
        tk.Checkbutton(self.char_frame, text="Numbers", variable=self.digit_var, bg="#ECF0F1").grid(row=1, column=0, sticky="w")
        tk.Checkbutton(self.char_frame, text="Symbols", variable=self.symbol_var, bg="#ECF0F1").grid(row=1, column=1, sticky="w")

        # Reference Words Input
        self.ref_label = tk.Label(root, text="Reference Words (comma-separated):", font=("Arial", 12), bg="#ECF0F1")
        self.ref_label.pack(pady=5)
        self.ref_entry = tk.Entry(root, width=50)
        self.ref_entry.pack(pady=5)

        # Generate Button
        self.generate_btn = tk.Button(root, text="Generate Passwords", font=("Arial", 12, "bold"), bg="#3498DB", fg="white", command=self.generate_passwords)
        self.generate_btn.pack(pady=10, ipadx=10)

        # Scrollable Password Display
        self.result_frame = tk.Frame(root, bg="#ECF0F1")
        self.result_frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.canvas = tk.Canvas(self.result_frame, bg="grey")
        self.scrollbar = ttk.Scrollbar(self.result_frame, orient="vertical", command=self.canvas.yview)
        self.password_list = tk.Frame(self.canvas, bg="#ECF0F1")

        self.password_list.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))

        self.canvas.create_window((0, 0), window=self.password_list, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        self.canvas.pack(side="left", fill="x", expand=True)
        self.scrollbar.pack(side="right", fill="y")

        # Copy & Save Buttons
        self.button_frame = tk.Frame(root, bg="#ECF0F1")
        self.button_frame.pack(pady=10)

        self.copy_all_btn = tk.Button(self.button_frame, text="Copy All", bg="#2ECC71", fg="white", command=self.copy_all_passwords)
        self.copy_all_btn.pack(side="left", padx=5)

        self.save_btn = tk.Button(self.button_frame, text="Save to File", bg="#F39C12", fg="white", command=self.save_to_file)
        self.save_btn.pack(side="left", padx=5)

    def generate_passwords(self):
        for widget in self.password_list.winfo_children():
            widget.destroy()

        try:
            num_passwords = self.num_var.get()
            if num_passwords < 1 or num_passwords > 50:
                raise ValueError("Enter a number between 1 and 50")

        except ValueError:
            messagebox.showerror("Invalid Input", "Please enter a valid number of passwords.")
            return

        passwords = [self.generate_password() for _ in range(num_passwords)]

        for i, password in enumerate(passwords, start=1):
            frame = tk.Frame(self.password_list, bg="grey")
            frame.pack(fill="x", pady=2)

            tk.Label(frame, text=f"{i}.", width=5, anchor="w", bg="grey",fg="white").pack(side="left",padx=95)
            tk.Label(frame, text=password, width=40, anchor="w", bg="grey",fg="white").pack(side="left")
            tk.Button(frame, text="Copy", command=lambda p=password: self.copy_to_clipboard(p), bg="#2ECC71", fg="#ECF0F1").pack(side="right")

    def generate_password(self):
        length = self.length_var.get()
        references = self.ref_entry.get()
        character_pool = ""

        if self.upper_var.get():
            character_pool += string.ascii_uppercase
        if self.lower_var.get():
            character_pool += string.ascii_lowercase
        if self.digit_var.get():
            character_pool += string.digits
        if self.symbol_var.get():
            character_pool += string.punctuation

        custom_words = self.process_reference_words(references)
        password_parts = random.choices(character_pool, k=length)
        return ''.join(password_parts)

    def process_reference_words(self, references):
        words = [word.strip() for word in references.split(",") if word.strip()]
        return words

    def copy_to_clipboard(self, password):
        pyperclip.copy(password)
        messagebox.showinfo("Copied!", "Password copied to clipboard.")

    def copy_all_passwords(self):
        all_passwords = "\n".join([child.winfo_children()[1].cget("text") for child in self.password_list.winfo_children()])
        pyperclip.copy(all_passwords)
        messagebox.showinfo("Copied!", "All passwords copied to clipboard.")

    def save_to_file(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
        if file_path:
            with open(file_path, "w") as file:
                for child in self.password_list.winfo_children():
                    file.write(child.winfo_children()[1].cget("text") + "\n")

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordGeneratorApp(root)
    root.mainloop()