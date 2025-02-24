import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import os
import shutil
import mysql.connector

# Suspicious file extensions
SUSPICIOUS_EXTENSIONS = {".exe", ".bat", ".cmd", ".vbs", ".scr", ".ps1", ".js"}

# Malicious keywords to check in file content
MALICIOUS_KEYWORDS = {"powershell", "cmd.exe", "exec(", "eval(", "system(", "subprocess", "import os", "wget", "curl"}

# Quarantine folder
QUARANTINE_FOLDER = "Quarantine"
os.makedirs(QUARANTINE_FOLDER, exist_ok=True)  # Create quarantine folder if not exists

# MySQL Database connection
def connect_to_db():
    try:
        # Replace with your MySQL connection details
        connection = mysql.connector.connect(
            host="localhost",  
            user="root",       
            password="", 
            database="malware_scanning_tool"  
        )
        return connection
    except mysql.connector.Error as err:
        messagebox.showerror("Database Error", f"Error: {err}")
        return None

def login():
    username = login_username_entry.get()
    password = login_password_entry.get()
    connection = connect_to_db()
    if connection:
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM users WHERE username = %s AND password = %s", (username, password))
        user = cursor.fetchone()
        cursor.close()
        connection.close()

        if user:
            messagebox.showinfo("Login Successful", f"Welcome, {username}!")
            show_main_window()
        else:
            messagebox.showerror("Login Failed", "Invalid username or password")

def register():
    username = register_username_entry.get()
    password = register_password_entry.get()
    if not username or not password:  # Ensure both fields are not empty
        messagebox.showerror("Error", "Username and password are required!")
        return
    connection = connect_to_db()
    if connection:
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        existing_user = cursor.fetchone()
        if existing_user:
            messagebox.showerror("Registration Failed", "Username already exists")
        else:
            cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, password))
            connection.commit()
            messagebox.showinfo("Registration Successful", f"Account created for {username}!")
            show_login_window()

        cursor.close()
        connection.close()

def show_main_window():
    login_frame.pack_forget()  # Hide login/register
    register_frame.pack_forget()  # Hide registration frame
    malware_frame.pack(pady=10)  # Show malware scanner

def show_login_window():
    malware_frame.pack_forget()  # Hide malware scanner
    login_frame.pack(pady=10)  # Show login/register
    register_frame.pack_forget()  # Hide registration frame

def show_register_window():
    login_frame.pack_forget()  # Hide login frame
    register_frame.pack(pady=10)  # Show registration frame

# Malware scanner functionality
def scan_file():
    file_path = filedialog.askopenfilename()
    if not file_path:
        return
    result = check_file(file_path)
    update_log(result)

def scan_folder():
    folder_path = filedialog.askdirectory()
    if not folder_path:
        return

    results = []
    for root, _, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            results.append(check_file(file_path))
    
    update_log("\n".join(results))

def check_file(file_path):
    extension = os.path.splitext(file_path)[-1].lower()
    is_suspicious_extension = extension in SUSPICIOUS_EXTENSIONS
    is_suspicious_content = False

    try:
        with open(file_path, "r", errors="ignore") as file:
            content = file.read().lower()
            for keyword in MALICIOUS_KEYWORDS:
                if keyword in content:
                    is_suspicious_content = True
                    break
    except Exception as e:
        return f"⚠ Could not read file: {file_path} ({e})"

    if is_suspicious_extension or is_suspicious_content:
        return f"⚠ Malware Detected: {file_path} (Quarantined)"
    else:
        return f"✅ Safe: {file_path}"

def update_log(message):
    scan_log.insert(tk.END, message + "\n")
    scan_log.yview(tk.END)

def move_to_quarantine():
    lines = scan_log.get("1.0", tk.END).strip().split("\n")
    moved_files = []
    
    for line in lines:
        if "⚠ Malware Detected" in line:
            file_path = line.split(": ")[1].split(" (")[0]
            if os.path.exists(file_path):
                filename = os.path.basename(file_path)
                new_path = os.path.join(QUARANTINE_FOLDER, filename)
                shutil.move(file_path, new_path)
                moved_files.append(f"Moved to Quarantine: {filename}")
    
    if moved_files:
        update_log("\n".join(moved_files))
        messagebox.showinfo("Quarantine", "Suspicious files moved to Quarantine!")
    else:
        messagebox.showinfo("Quarantine", "No suspicious files to move.")

def view_quarantine():
    quarantine_files = os.listdir(QUARANTINE_FOLDER)
    quarantine_list.delete(0, tk.END)
    
    if not quarantine_files:
        messagebox.showinfo("Quarantine", "No files in quarantine.")
        return
    
    for file in quarantine_files:
        quarantine_list.insert(tk.END, file)

def restore_file():
    selected_file = quarantine_list.get(tk.ACTIVE)
    if not selected_file:
        return

    original_path = filedialog.askdirectory()
    if not original_path:
        return
    
    src = os.path.join(QUARANTINE_FOLDER, selected_file)
    dest = os.path.join(original_path, selected_file)

    shutil.move(src, dest)
    quarantine_list.delete(tk.ACTIVE)
    messagebox.showinfo("Restore", f"File restored to {original_path}")

def delete_file():
    selected_file = quarantine_list.get(tk.ACTIVE)
    if not selected_file:
        return

    confirmation = messagebox.askyesno("Delete File", f"Are you sure you want to permanently delete '{selected_file}'?")
    if confirmation:
        file_path = os.path.join(QUARANTINE_FOLDER, selected_file)
        os.remove(file_path)
        quarantine_list.delete(tk.ACTIVE)
        messagebox.showinfo("Delete", f"File '{selected_file}' has been deleted.")

# GUI Setup
root = tk.Tk()
root.title("Malware Detection and Removal Tools")
root.configure(bg="#ADD8E6")

# Custom Color Scheme
bg_color = "#ADD8E6"  # Soft Blue Background
button_color = "#4CAF50"  # Green Buttons
highlight_color = "#FF5733"  # Orange Highlight
text_color = "#333333"  # Dark Text
entry_bg_color = "#e6e6e6"  # Light Gray Background for Entry Fields

# Login Frame
login_frame = tk.Frame(root, padx=20, pady=20, bg=bg_color)
login_frame.pack(pady=10)

login_label = tk.Label(login_frame, text="Login", font=("Arial", 16, "bold"), fg=highlight_color, bg=bg_color)
login_label.pack(pady=10)

login_username_label = tk.Label(login_frame, text="Username", fg=text_color, bg=bg_color)
login_username_label.pack()

login_username_entry = tk.Entry(login_frame, bg=entry_bg_color)
login_username_entry.pack()

login_password_label = tk.Label(login_frame, text="Password", fg=text_color, bg=bg_color)
login_password_label.pack()

login_password_entry = tk.Entry(login_frame, show="*", bg=entry_bg_color)
login_password_entry.pack()

login_button = tk.Button(login_frame, text="Login", command=login, bg=button_color, fg="white")
login_button.pack(pady=5)

register_button = tk.Button(login_frame, text="Register", command=show_register_window, bg=highlight_color, fg="white")
register_button.pack()

# Register Frame
register_frame = tk.Frame(root, padx=20, pady=20, bg=bg_color)

register_label = tk.Label(register_frame, text="Register", font=("Arial", 16, "bold"), fg=highlight_color, bg=bg_color)
register_label.pack(pady=10)

register_username_label = tk.Label(register_frame, text="Username", fg=text_color, bg=bg_color)
register_username_label.pack()

register_username_entry = tk.Entry(register_frame, bg=entry_bg_color)
register_username_entry.pack()

register_password_label = tk.Label(register_frame, text="Password", fg=text_color, bg=bg_color)
register_password_label.pack()

register_password_entry = tk.Entry(register_frame, show="*", bg=entry_bg_color)
register_password_entry.pack()

register_button = tk.Button(register_frame, text="Register", command=register, bg=button_color, fg="white")
register_button.pack(pady=5)

# Main malware scanner frame
malware_frame = tk.Frame(root, padx=20, pady=20, bg=bg_color)

# Scanner controls here
title_label = tk.Label(malware_frame, text="🔍 Malware Scanner", font=("Arial", 16, "bold"), fg=highlight_color, bg=bg_color)
title_label.pack()

scan_file_button = tk.Button(malware_frame, text="📂 Scan File", command=scan_file, bg=button_color, fg="white")
scan_file_button.pack(pady=5)

scan_folder_button = tk.Button(malware_frame, text="📁 Scan Folder", command=scan_folder, bg=button_color, fg="white")
scan_folder_button.pack(pady=5)

quarantine_button = tk.Button(malware_frame, text="🚫 Move to Quarantine", command=move_to_quarantine, bg=highlight_color, fg="white")
quarantine_button.pack(pady=5)

view_quarantine_button = tk.Button(malware_frame, text="🔎 View Quarantine", command=view_quarantine, bg=highlight_color, fg="white")
view_quarantine_button.pack(pady=5)

# Log area (scan_log definition)
scan_log = tk.Text(malware_frame, width=60, height=10, wrap=tk.WORD, bg=entry_bg_color)
scan_log.pack(pady=10)

# Quarantine File Management
restore_button = tk.Button(malware_frame, text="Restore File", command=restore_file, bg=button_color, fg="white")
restore_button.pack(pady=5)

delete_button = tk.Button(malware_frame, text="Delete File", command=delete_file, bg=button_color, fg="white")
delete_button.pack(pady=5)

# Quarantine List
quarantine_list = tk.Listbox(malware_frame, width=50, height=10, bg=entry_bg_color)
quarantine_list.pack(pady=10)

# Start with login window
show_login_window()

root.mainloop()
