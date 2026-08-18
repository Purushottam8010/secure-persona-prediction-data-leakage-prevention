# create_structure.py
import os

# Create directories
directories = [
    "app",
    "app/dashboard",
    "app/security",
    "app/services",
    "app/database",
    "config",
    "data",
    ".streamlit"
]

for directory in directories:
    os.makedirs(directory, exist_ok=True)
    print(f"Created: {directory}")

# Create __init__.py files
init_files = [
    "app/__init__.py",
    "app/dashboard/__init__.py",
    "app/security/__init__.py",
    "app/services/__init__.py",
    "app/database/__init__.py",
    "config/__init__.py"
]

for init_file in init_files:
    with open(init_file, 'w') as f:
        f.write("# Package initialization\n")
    print(f"Created: {init_file}")

print("\n✅ Project structure created!")