import hashlib
import os
import tkinter as tk
from tkinter import ttk, messagebox
import threading

# --- Hashing Functions ---

def generate_md5_hash(input_string):
    """
    Generates the MD5 hash for a given input string.
    MD5 is cryptographically broken and should not be used for security-sensitive
    applications like password storage due to collision vulnerabilities.
    """
    md5_hash = hashlib.md5(input_string.encode('utf-8')).hexdigest()
    return md5_hash

def generate_basic_sha256_hash(input_string):
    """
    Generates a basic SHA256 hash for a given input string, without salting
    or multiple rounds. This is primarily for integrity checks, not secure
    password storage.
    """
    basic_sha256_hash = hashlib.sha256(input_string.encode('utf-8')).hexdigest()
    return basic_sha256_hash

def generate_secure_sha256_hash(input_string, salt=None, rounds=100000):
    """
    Generates the SHA256 hash for a given input string, incorporating salting
    and multiple rounds (iterations) for enhanced security, especially for
    password storage.
    """
    if salt is None:
        salt = os.urandom(16)
    
    salted_input = salt + input_string.encode('utf-8')

    current_hash = salted_input
    for _ in range(rounds):
        current_hash = hashlib.sha256(current_hash).digest() # Use .digest() for bytes output

    hex_hash = current_hash.hex()
    hex_salt = salt.hex()

    return hex_hash, hex_salt

# --- Page Classes for Tkinter GUI ---

class HashingPage(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, padding=0, style='TFrame')
        self.controller = controller

        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        self.canvas = tk.Canvas(self, borderwidth=0, background='#F0F4F8', highlightthickness=0)
        self.scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        
        self.canvas.grid(row=0, column=0, sticky="nsew")
        self.scrollbar.grid(row=0, column=1, sticky="ns")

        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        self.scrollable_frame = ttk.Frame(self.canvas, padding=10, style='TFrame')
        self.canvas_window_id = self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")

        self.scrollable_frame.bind("<Configure>", self.on_frame_configure)
        self.canvas.bind("<Configure>", self.on_canvas_resize)

        # --- Configure grid for the scrollable_frame content ---
        self.scrollable_frame.grid_columnconfigure(0, weight=1) 
        self.scrollable_frame.grid_columnconfigure(1, weight=1)
        
        # --- Widgets for MD5, Basic SHA256 (now 2 columns) ---
        self.create_basic_hash_section(self.scrollable_frame, 0, 0, "MD5 Hashing (Insecure)",
                                     self.do_md5_hash, 'md5_input', 'md5_result',
                                     "⚠️ WARNING: MD5 is cryptographically broken! Do NOT use MD5 for password storage or data integrity checks in new applications.",
                                     '#FBE6E6', '#E74C3C', 'Red.TButton') # Red tones for warning
        
        self.create_basic_hash_section(self.scrollable_frame, 0, 1, "SHA256 Hashing (Basic)",
                                     self.do_sha256_basic_hash, 'sha256_basic_input', 'sha256_basic_result',
                                     "✅ Good for Integrity Checks. For passwords, add salt and rounds.",
                                     '#E6F3FA', '#4A90E2', 'TButton') # Blue tones for informative

        # --- Widgets for Secure SHA256 ---
        # This section spans both columns in the next row.
        secure_sha256_frame = ttk.LabelFrame(self.scrollable_frame, text="SHA256 Hashing (Secure)", padding=15, style='TLabelframe')
        secure_sha256_frame.grid(row=1, column=0, columnspan=2, sticky="ew", padx=10, pady=10)
        secure_sha256_frame.grid_columnconfigure(0, weight=1)
        secure_sha256_frame.grid_columnconfigure(1, weight=1)

        ttk.Label(secure_sha256_frame, text="🔒 Recommended for Password Storage",
                  style='InfoBox.TLabel').grid(row=0, column=0, columnspan=2, sticky="ew", pady=5, padx=5)
        ttk.Label(secure_sha256_frame, text="SHA256, especially with salting and multiple rounds, provides robust security against common attacks.",
                  font=('Segoe UI', 9), foreground='#27AE60', background='#FFFFFF').grid(row=1, column=0, columnspan=2, sticky="ew", pady=2, padx=5)

        ttk.Label(secure_sha256_frame, text="Enter text:", style='TLabel').grid(row=2, column=0, sticky="w", pady=(10,2), padx=5)
        self.secure_sha256_input = ttk.Entry(secure_sha256_frame, style='TEntry') 
        self.secure_sha256_input.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(0,10), padx=5)
        self.secure_sha256_input.insert(0, "SecurePassword123")

        ttk.Label(secure_sha256_frame, text="Number of Rounds (e.g., 100000):", style='TLabel').grid(row=4, column=0, sticky="w", pady=(0,2), padx=5)
        self.rounds_input = ttk.Entry(secure_sha256_frame, style='TEntry')
        self.rounds_input.grid(row=5, column=0, sticky="ew", pady=(0,10), padx=5)
        self.rounds_input.insert(0, "100000")
        ttk.Label(secure_sha256_frame, text="Higher rounds make brute-force harder.", font=('Segoe UI', 8), foreground='#607D8B', background='#FFFFFF').grid(row=5, column=1, sticky="w", padx=5)

        ttk.Button(secure_sha256_frame, text="Generate Secure SHA256 Hash", command=self.do_secure_sha256_hash, style='Green.TButton').grid(row=6, column=0, columnspan=2, sticky="ew", pady=10, padx=5)

        ttk.Label(secure_sha256_frame, text="SHA256 Hash:", style='TLabel').grid(row=7, column=0, sticky="w", pady=(5,0), padx=5)
        self.secure_sha256_result_label = ttk.Label(secure_sha256_frame, text="", justify='left', style='Result.TLabel', anchor='w')
        self.secure_sha256_result_label.grid(row=8, column=0, columnspan=2, sticky="ew", pady=(0,5), padx=5)
        self.secure_sha256_result_label.bind("<Configure>", lambda e, w=secure_sha256_frame: self.secure_sha256_result_label.config(wraplength=w.winfo_width()-30))

        ttk.Label(secure_sha256_frame, text="Salt Used:", style='TLabel').grid(row=9, column=0, sticky="w", pady=(5,0), padx=5)
        self.secure_sha256_salt_label = ttk.Label(secure_sha256_frame, text="", justify='left', style='Result.TLabel', anchor='w')
        self.secure_sha256_salt_label.grid(row=10, column=0, columnspan=2, sticky="ew", pady=(0,5), padx=5)
        self.secure_sha256_salt_label.bind("<Configure>", lambda e, w=secure_sha256_frame: self.secure_sha256_salt_label.config(wraplength=w.winfo_width()-30))

        ttk.Label(secure_sha256_frame, text="Rounds:", style='TLabel').grid(row=11, column=0, sticky="w", pady=(5,0), padx=5)
        self.secure_sha256_rounds_label = ttk.Label(secure_sha256_frame, text="", style='Result.TLabel', anchor='w')
        self.secure_sha256_rounds_label.grid(row=12, column=0, columnspan=2, sticky="ew", pady=(0,5), padx=5)


    def on_frame_configure(self, event):
        """Update the scrollregion of the canvas based on the scrollable frame's size."""
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def on_canvas_resize(self, event):
        """Adjust the width of the scrollable frame when the canvas (window) is resized."""
        self.canvas.itemconfig(self.canvas_window_id, width=event.width)

    def create_basic_hash_section(self, parent_frame, row, column, title, hash_command, input_id, result_id, explanation, bg_color, text_color, button_style):
        frame = ttk.LabelFrame(parent_frame, text=title, padding=15, style='TLabelframe')
        frame.grid(row=row, column=column, sticky="nsew", padx=10, pady=10)
        frame.grid_columnconfigure(0, weight=1)

        ttk.Label(frame, text=explanation, font=('Segoe UI', 9), foreground=text_color, background=bg_color, relief='solid', borderwidth=1, padding=5).grid(row=0, column=0, sticky="ew", pady=5, padx=5)

        ttk.Label(frame, text="Enter text:", style='TLabel').grid(row=1, column=0, sticky="w", pady=(10,2), padx=5)
        input_entry = ttk.Entry(frame, style='TEntry')
        input_entry.grid(row=2, column=0, sticky="ew", pady=(0,10), padx=5)
        setattr(self, input_id, input_entry)

        ttk.Button(frame, text=f"Generate {title.split(' ')[0]} Hash", command=hash_command, style=button_style).grid(row=3, column=0, sticky="ew", pady=10, padx=5)

        ttk.Label(frame, text="Hash:", style='TLabel').grid(row=4, column=0, sticky="w", pady=(5,0), padx=5)
        result_label = ttk.Label(frame, text="", justify='left', style='Result.TLabel', anchor='w')
        result_label.grid(row=5, column=0, sticky="ew", pady=(0,5), padx=5)
        setattr(self, result_id, result_label)
        result_label.bind("<Configure>", lambda e, w=frame: result_label.config(wraplength=w.winfo_width()-30))

    def do_md5_hash(self):
        input_text = self.md5_input.get()
        if not input_text:
            messagebox.showwarning("Input Error", "Please enter text for MD5 hashing.")
            return
        
        self.md5_result.config(text="Calculating...", foreground='#333333')
        hash_val = generate_md5_hash(input_text)
        self.md5_result.config(text=hash_val, foreground='#2c3e50')

    def do_sha256_basic_hash(self):
        input_text = self.sha256_basic_input.get()
        if not input_text:
            messagebox.showwarning("Input Error", "Please enter text for Basic SHA256 hashing.")
            return
        
        self.sha256_basic_result.config(text="Calculating...", foreground='#333333')
        hash_val = generate_basic_sha256_hash(input_text)
        self.sha256_basic_result.config(text=hash_val, foreground='#2c3e50')

    def do_secure_sha256_hash(self):
        input_text = self.secure_sha256_input.get()
        rounds_str = self.rounds_input.get()

        if not input_text:
            messagebox.showwarning("Input Error", "Please enter text for Secure SHA256 hashing.")
            return

        try:
            rounds = int(rounds_str)
            if rounds < 1000:
                messagebox.showwarning("Rounds Warning", "Number of rounds is too low for real-world security. Using 100000.")
                rounds = 100000
                self.rounds_input.delete(0, tk.END)
                self.rounds_input.insert(0, str(rounds))
        except ValueError:
            messagebox.showwarning("Input Error", "Invalid number of rounds. Please enter a whole number.")
            return
        
        self.secure_sha256_result_label.config(text="Calculating...", foreground='#333333')
        self.secure_sha256_salt_label.config(text="", foreground='#333333')
        self.secure_sha256_rounds_label.config(text="", foreground='#333333')

        thread = threading.Thread(target=self._run_secure_sha256_threaded, args=(input_text, rounds))
        thread.start()

    def _run_secure_sha256_threaded(self, input_text, rounds):
        try:
            hash_val, salt_val = generate_secure_sha256_hash(input_text, rounds=rounds)
            self.controller.master.after(0, self._update_secure_sha256_results, hash_val, salt_val, rounds)
        except Exception as e:
            self.controller.master.after(0, lambda: messagebox.showerror("Hashing Error", f"An error occurred: {e}"))
            self.controller.master.after(0, self._update_secure_sha256_results, "Error!", "", "")

    def _update_secure_sha256_results(self, hash_val, salt_val, rounds):
        self.secure_sha256_result_label.config(text=hash_val, foreground='#2c3e50')
        self.secure_sha256_salt_label.config(text=salt_val, foreground='#2c3e50')
        self.secure_sha256_rounds_label.config(text=str(rounds), foreground='#2c3e50')


class AboutPage(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, padding=20, style='TFrame')
        self.controller = controller
        
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=0) # Title
        self.grid_rowconfigure(1, weight=1) # Text widget
        self.grid_rowconfigure(2, weight=0) # Spacer if needed

        ttk.Label(self, text="About This Application", font=('Segoe UI', 20, 'bold'), foreground='#2C3E50', background='#F0F4F8').grid(row=0, column=0, pady=10)
        
        about_text = """
        This Hashing Demonstration application is built using Python's Tkinter library.
        It provides an interactive way to explore various cryptographic hash functions:

        -   **MD5 (Message Digest Algorithm 5):** An older hash function now considered cryptographically broken, especially vulnerable to collision attacks. It's included for educational purposes to highlight why it should no longer be used for security-sensitive tasks like password storage or data integrity verification.
        -   **SHA256 (Secure Hash Algorithm 256):** A part of the SHA-2 family, currently considered strong and widely used for data integrity, digital signatures, and secure password hashing.
        -   **Secure SHA256 (with Salt and Rounds):** This demonstrates best practices for password storage. 'Salting' adds uniqueness to each hash, preventing rainbow table attacks. 'Multiple Rounds' (key stretching) intentionally slows down the hashing process, making brute-force attacks computationally expensive and impractical for attackers.

        Developed for educational purposes to illustrate fundamental concepts in computer security and cryptography.

        ---

        **Project Details:**
        Course: CSC662: COMPUTER SECURITY
        Group Project: CDCS2306B
        Final Project: Hash Function

        **Prepared For:**
        DR. FERAS ZEN ALDEN

        **Group Members:**
        - NUR NABILAH BINTI ARWIN (2022621952)
        - MUHAMMAD NABIL BIN DZULKARNAIN (2023874026)
        - ABDULLAH BIN HARUN (2023687236)
        - AHMAD HUSAINI BIN MOHD SHAFFIN (2023607522)
        """
        about_text_widget = tk.Text(self, wrap="word", font=('Segoe UI', 10), background='#FFFFFF', foreground='#34495E', relief='solid', borderwidth=1, padx=10, pady=10)
        about_text_widget.insert(tk.END, about_text.strip())
        about_text_widget.config(state=tk.DISABLED)
        about_text_widget.grid(row=1, column=0, pady=10, padx=20, sticky="nsew")

        about_scrollbar = ttk.Scrollbar(self, orient="vertical", command=about_text_widget.yview)
        about_scrollbar.grid(row=1, column=1, sticky="ns")
        about_text_widget.config(yscrollcommand=about_scrollbar.set)

# --- Main Tkinter Application Class ---

class HashingApp:
    def __init__(self, master):
        self.master = master
        master.title("Hashing Demonstration")
        master.geometry("1920x1080") # Fixed size
        master.resizable(False, False) # Prevent resizing

        # --- Styles ---
        style = ttk.Style()
        style.theme_use('clam')

        # Define a color palette
        COLOR_PRIMARY = '#4A90E2' # Blue
        COLOR_PRIMARY_DARK = '#357ABD' # Darker Blue
        COLOR_BACKGROUND_LIGHT = '#F0F4F8' # Light Gray/Blueish
        COLOR_BACKGROUND_WHITE = '#FFFFFF' # Pure White
        COLOR_TEXT_DARK = '#34495E' # Dark Blue-Gray
        COLOR_TEXT_MEDIUM = '#607D8B' # Medium Gray
        COLOR_TEXT_LIGHT = 'white'

        # Specific accent colors
        COLOR_RED = '#E74C3C'
        COLOR_RED_DARK = '#C0392B'
        COLOR_ORANGE = '#F39C12'
        COLOR_ORANGE_DARK = '#D35400'
        COLOR_GREEN = '#2ECC71'
        COLOR_GREEN_DARK = '#27AE60'
        COLOR_PURPLE = '#9B59B6'
        COLOR_PURPLE_DARK = '#8E44AD'

        style.configure('TFrame', background=COLOR_BACKGROUND_LIGHT)
        style.configure('TLabel', background=COLOR_BACKGROUND_LIGHT, foreground=COLOR_TEXT_DARK, font=('Segoe UI', 10))
        style.configure('Heading.TLabel', font=('Segoe UI', 24, 'bold'), foreground=COLOR_TEXT_DARK)
        style.configure('Subheading.TLabel', font=('Segoe UI', 12), foreground=COLOR_TEXT_MEDIUM)
        style.configure('Info.TLabel', font=('Segoe UI', 9), foreground=COLOR_TEXT_MEDIUM)
        
        style.configure('TLabelframe', background=COLOR_BACKGROUND_WHITE, borderwidth=1, relief='solid')
        style.configure('TLabelframe.Label', font=('Segoe UI', 14, 'bold'), foreground=COLOR_TEXT_DARK)
        
        style.configure('TEntry', fieldbackground=COLOR_BACKGROUND_WHITE, borderwidth=1, relief='solid', font=('Consolas', 10), foreground=COLOR_TEXT_DARK)
        
        style.configure('TButton', font=('Segoe UI', 10, 'bold'), padding=8, relief='flat', background=COLOR_PRIMARY, foreground=COLOR_TEXT_LIGHT)
        style.map('TButton',
                  background=[('active', COLOR_PRIMARY_DARK), ('pressed', COLOR_PRIMARY_DARK)],
                  foreground=[('active', COLOR_TEXT_LIGHT), ('pressed', COLOR_TEXT_LIGHT)],
                  relief=[('pressed', 'groove'), ('!pressed', 'flat')])
        
        style.configure('Red.TButton', background=COLOR_RED)
        style.map('Red.TButton', background=[('active', COLOR_RED_DARK), ('pressed', COLOR_RED_DARK)])
        
        style.configure('Orange.TButton', background=COLOR_ORANGE)
        style.map('Orange.TButton', background=[('active', COLOR_ORANGE_DARK), ('pressed', COLOR_ORANGE_DARK)])
        
        style.configure('Green.TButton', background=COLOR_GREEN)
        style.map('Green.TButton', background=[('active', COLOR_GREEN_DARK), ('pressed', COLOR_GREEN_DARK)])
        
        style.configure('Purple.TButton', background=COLOR_PURPLE)
        style.map('Purple.TButton', background=[('active', COLOR_PURPLE_DARK), ('pressed', COLOR_PURPLE_DARK)])
        
        style.configure('Result.TLabel', background=COLOR_BACKGROUND_LIGHT, foreground=COLOR_TEXT_DARK, font=('Consolas', 10),
                        borderwidth=1, relief='solid', padding=5)
        
        style.configure('Warning.TLabel', foreground=COLOR_RED, background='#FFEBEE', font=('Segoe UI', 9, 'bold')) # Lighter red background
        style.configure('InfoBox.TLabel', foreground=COLOR_PRIMARY_DARK, background='#E6F3FA', font=('Segoe UI', 9, 'bold')) # Lighter blue background

        # --- Main Layout Frames ---
        header_height = 120
        navbar_width = 250
        main_content_height = 1080 - header_height

        master.grid_columnconfigure(0, weight=0) 
        master.grid_columnconfigure(1, weight=0)
        master.grid_rowconfigure(0, weight=0)
        master.grid_rowconfigure(1, weight=0)

        self.header_frame = ttk.Frame(master, padding="20 15", style='TFrame', width=1920, height=header_height)
        self.header_frame.grid(row=0, column=0, columnspan=2, sticky="ew")
        self.header_frame.grid_propagate(False)

        ttk.Label(self.header_frame, text="Hashing Demonstration", style='Heading.TLabel').pack(pady=5)
        ttk.Label(self.header_frame, text="Explore MD5 and SHA256 with Salting & Rounds", style='Subheading.TLabel').pack()
        ttk.Label(self.header_frame, text="All hashing operations are performed locally within this Python application.", style='Info.TLabel').pack(pady=(0,10))
        ttk.Separator(self.header_frame, orient='horizontal').pack(fill='x', pady=10)

        self.navbar_frame = ttk.Frame(master, width=navbar_width, height=main_content_height, padding="10 20", style='TFrame', relief='solid', borderwidth=1)
        self.navbar_frame.grid(row=1, column=0, sticky="ns")
        self.navbar_frame.grid_propagate(False)

        ttk.Button(self.navbar_frame, text="Hashing Demos", command=lambda: self.show_page("Hashing Demos"), style='TButton').pack(fill='x', pady=5, padx=5)
        ttk.Button(self.navbar_frame, text="About", command=lambda: self.show_page("About"), style='TButton').pack(fill='x', pady=5, padx=5)

        content_area_width = 1920 - navbar_width
        self.content_frame = ttk.Frame(master, width=content_area_width, height=main_content_height, padding=10, style='TFrame')
        self.content_frame.grid(row=1, column=1, sticky="nsew")
        self.content_frame.grid_propagate(False)

        self.content_frame.grid_columnconfigure(0, weight=1)
        self.content_frame.grid_rowconfigure(0, weight=1)

        self.pages = {}
        self.pages["Hashing Demos"] = HashingPage(self.content_frame, self)
        self.pages["About"] = AboutPage(self.content_frame, self)

        for name, page in self.pages.items():
            page.grid(row=0, column=0, sticky="nsew")

        self.show_page("Hashing Demos")

    def show_page(self, page_name):
        page = self.pages[page_name]
        page.tkraise()


if __name__ == "__main__":
    root = tk.Tk()
    app = HashingApp(root)
    root.mainloop()
