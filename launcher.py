import subprocess
# Define the paths to your main programs
CLI_PROGRAM = "CLI_login.py"
GUI_PROGRAM = "GUI_login.py"

def launch_cli():
    """Launch the CLI-based program."""
    subprocess.run(["python", CLI_PROGRAM], check=True)

def launch_gui():
    """Launch the GUI-based program."""
    subprocess.run(["python", GUI_PROGRAM], check=True)

def main():
    """Menu-driven program to choose interface mode."""
    while True:
        print("\n=== Program Launcher ===")
        print("1. Launch CLI Mode")
        print("2. Launch GUI Mode")
        print("3. Exit")
        
        choice = input("Enter your choice (1/2/3): ").strip()

        if choice == "1":
            launch_cli()
        elif choice == "2":
            launch_gui()
        elif choice == "3":
            print("Exiting launcher.")
            break
        else:
            print("Invalid choice! Please enter 1, 2, or 3.")

if __name__ == "__main__":
    main()
