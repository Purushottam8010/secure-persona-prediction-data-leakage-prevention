import re

with open('database.py', 'r') as f:
    content = f.read()

# Fix all instances of unpacking
pattern = r'(\s+)conn,\s*cursor\s*=\s*self\.get_connection\(\)'
replacement = r'\1conn = self.get_connection()\n\1cursor = conn.cursor()'

fixed_content = re.sub(pattern, replacement, content)

with open('database.py', 'w') as f:
    f.write(fixed_content)

print("Fixed all unpacking errors in database.py")