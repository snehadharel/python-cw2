import os
import shutil
import hashlib

# Suspicious file extensions
SUSPICIOUS_EXTENSIONS = {".exe", ".bat", ".cmd", ".vbs", ".scr", ".ps1", ".js"}

# Malicious keywords to check in file content
MALICIOUS_KEYWORDS = {"powershell", "cmd.exe", "exec(", "eval(", "system(", "subprocess", "import os", "wget", "curl"}

# Quarantine folder
QUARANTINE_FOLDER = "Quarantine"
os.makedirs(QUARANTINE_FOLDER, exist_ok=True)  # Create quarantine folder if not exists

# Path for storing user credentials
USER_CREDENTIALS_FILE = "user_credentials.txt"

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def register_user():
    username = input("Enter a username: ")
    password = input("Enter a password: ")
    hashed_password = hash_password(password)

    # Store credentials in a file
    with open(USER_CREDENTIALS_FILE, "a") as file:
        file.write(f"{username},{hashed_password}\n")
    
    print("User registered successfully!")


def login_user():
    username = input("Enter username: ")
    password = input("Enter password: ")
    hashed_password = hash_password(password)

    # Check if credentials are in the file
    if os.path.exists(USER_CREDENTIALS_FILE):
        with open(USER_CREDENTIALS_FILE, "r") as file:
            users = file.readlines()
            for user in users:
                stored_username, stored_password = user.strip().split(",")
                if stored_username == username and stored_password == hashed_password:
                    return True
    return False

def scan_file(file_path):
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

def scan_folder(folder_path):
    results = []
    for root, _, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            results.append(scan_file(file_path))
    
    return "\n".join(results)

def move_to_quarantine(scan_results):
    moved_files = []
    
    lines = scan_results.strip().split("\n")
    for line in lines:
        if "⚠ Malware Detected" in line:
            file_path = line.split(": ")[1].split(" (")[0]
            if os.path.exists(file_path):
                filename = os.path.basename(file_path)
                new_path = os.path.join(QUARANTINE_FOLDER, filename)
                shutil.move(file_path, new_path)
                moved_files.append(f"Moved to Quarantine: {filename}")
    
    if moved_files:
        return "\n".join(moved_files)
    else:
        return "No suspicious files to move."

def view_quarantine():
    quarantine_files = os.listdir(QUARANTINE_FOLDER)
    if not quarantine_files:
        return "No files in quarantine."
    
    return "\n".join(quarantine_files)

def restore_file(file_name):
    original_path = input(f"Enter destination directory to restore '{file_name}': ")
    if not original_path:
        return "Restoration cancelled."

    src = os.path.join(QUARANTINE_FOLDER, file_name)
    dest = os.path.join(original_path, file_name)

    shutil.move(src, dest)
    return f"File '{file_name}' restored to {original_path}"

def delete_file(file_name):
    confirmation = input(f"Are you sure you want to permanently delete '{file_name}'? (yes/no): ")
    if confirmation.lower() == "yes":
        file_path = os.path.join(QUARANTINE_FOLDER, file_name)
        os.remove(file_path)
        return f"File '{file_name}' has been deleted."
    else:
        return "File deletion cancelled."

def main():
    print("Welcome to the Malware Scanner!")

    while True:
        print("\n1. Register")
        print("2. Login")
        choice = input("Choose an option: ")

        if choice == "1":
            register_user()
        elif choice == "2":
            if login_user():
                print("Login successful!")

                # Main menu after login
                while True:
                    print("\nMalware Scanner CLI")
                    print("1. Scan File")
                    print("2. Scan Folder")
                    print("3. Move Suspicious Files to Quarantine")
                    print("4. View Quarantine Files")
                    print("5. Restore File from Quarantine")
                    print("6. Delete File from Quarantine")
                    print("7. Logout")
                    print("8. Exit")

                    choice = input("\nChoose an option: ")
                    if choice == "1":
                        file_path = input("Enter file path to scan: ")
                        result = scan_file(file_path)
                        print(result)

                    elif choice == "2":
                        folder_path = input("Enter folder path to scan: ")
                        result = scan_folder(folder_path)
                        print(result)

                    elif choice == "3":
                        scan_results = input("Paste scan results to move suspicious files to quarantine: ")
                        result = move_to_quarantine(scan_results)
                        print(result)

                    elif choice == "4":
                        print("Quarantine Files:")
                        print(view_quarantine())

                    elif choice == "5":
                        file_name = input("Enter file name to restore: ")
                        result = restore_file(file_name)
                        print(result)

                    elif choice == "6":
                        file_name = input("Enter file name to delete: ")
                        result = delete_file(file_name)
                        print(result)

                    elif choice == "7":
                        print("Logging out...")
                        break

                    elif choice == "8":
                        print("Exiting Malware Scanner CLI. Goodbye!")
                        exit()

                    else:
                        print("Invalid option. Please try again.")
            else:
                print("Invalid username or password. Please try again.")

        else:
            print("Invalid option. Please try again.")

if __name__ == "__main__":
    main()
