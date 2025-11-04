# utils/cli_utils.py

def ask_yes_no(question):
    """Prompt the user with a yes/no question and return True for yes, False for no."""
    while True:
        choice = input(f"{question} (y/n): ").strip().lower()
        if choice in ['y', 'yes']:
            return True
        elif choice in ['n', 'no']:
            return False
        else:
            print("Please enter 'y' or 'n'.")
