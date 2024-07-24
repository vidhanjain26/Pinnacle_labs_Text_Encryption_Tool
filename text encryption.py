import tkinter as tk
from tkinter import messagebox, simpledialog, ttk, filedialog
from Crypto.Cipher import AES, DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64
import os

# Paths for saving keys
DESKTOP_PATH = os.path.join(os.path.expanduser("~"), "Desktop")
LOGS_FOLDER = os.path.join(DESKTOP_PATH, "logs")
AES_KEY_PATH = os.path.join(LOGS_FOLDER, "aes_key.key")
DES_KEY_PATH = os.path.join(LOGS_FOLDER, "des_key.key")
RSA_PRIVATE_KEY_PATH = os.path.join(LOGS_FOLDER, "rsa_private_key.pem")
RSA_PUBLIC_KEY_PATH = os.path.join(LOGS_FOLDER, "rsa_public_key.pem")

# AES Key Generation
def generate_aes_key(key_size=32):
    return get_random_bytes(key_size)

# DES Key Generation
def generate_des_key():
    return get_random_bytes(8)  # DES key size is 8 bytes

# RSA Key Generation
def generate_rsa_key(key_size=2048):
    key = RSA.generate(key_size)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def encrypt_aes(plaintext, key):
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(plaintext.encode(), AES.block_size)
    ciphertext = cipher.encrypt(padded_data)
    return base64.b64encode(iv + ciphertext).decode('utf-8')

def decrypt_aes(encoded, key):
    raw_data = base64.b64decode(encoded)
    iv = raw_data[:AES.block_size]
    ciphertext = raw_data[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext)
    return unpad(padded_plaintext, AES.block_size).decode('utf-8')

def encrypt_des(plaintext, key):
    iv = get_random_bytes(DES.block_size)
    cipher = DES.new(key, DES.MODE_CBC, iv)
    padded_data = pad(plaintext.encode(), DES.block_size)
    ciphertext = cipher.encrypt(padded_data)
    return base64.b64encode(iv + ciphertext).decode('utf-8')

def decrypt_des(encoded, key):
    raw_data = base64.b64decode(encoded)
    iv = raw_data[:DES.block_size]
    ciphertext = raw_data[DES.block_size:]
    cipher = DES.new(key, DES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext)
    return unpad(padded_plaintext, DES.block_size).decode('utf-8')

def encrypt_rsa(plaintext, public_key):
    key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(key)
    ciphertext = cipher.encrypt(plaintext.encode())
    return base64.b64encode(ciphertext).decode('utf-8')

def decrypt_rsa(encoded, private_key):
    raw_data = base64.b64decode(encoded)
    key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(key)
    plaintext = cipher.decrypt(raw_data)
    return plaintext.decode('utf-8')

def save_log(action, method, plaintext, ciphertext):
    os.makedirs(LOGS_FOLDER, exist_ok=True)
    log_file = os.path.join(LOGS_FOLDER, "encryption_logs.txt")
    with open(log_file, "a") as f:
        f.write(f"{action} - Method: {method}\n")
        f.write(f"Plaintext: {plaintext}\n")
        f.write(f"Ciphertext: {ciphertext}\n")
        f.write("\n")

def save_key(key, filename):
    os.makedirs(LOGS_FOLDER, exist_ok=True)
    key_path = os.path.join(LOGS_FOLDER, filename)
    with open(key_path, "wb") as f:
        f.write(key)

def load_key(filename):
    key_path = os.path.join(LOGS_FOLDER, filename)
    if os.path.exists(key_path):
        with open(key_path, "rb") as f:
            return f.read()
    return None

class EncryptionTool:
    def __init__(self, root):
        self.root = root
        self.root.title("Encryption Tool")
        self.root.geometry("600x450")
        self.root.configure(bg="#1e1e1e")

        self.load_existing_keys()
        self.check_password()

    def load_existing_keys(self):
        self.aes_key = load_key("aes_key.key")
        self.des_key = load_key("des_key.key")
        self.rsa_private_key = load_key("rsa_private_key.pem")
        self.rsa_public_key = load_key("rsa_public_key.pem")

        if self.aes_key is None:
            self.aes_key = generate_aes_key()
            save_key(self.aes_key, "aes_key.key")
        if self.des_key is None:
            self.des_key = generate_des_key()
            save_key(self.des_key, "des_key.key")
        if self.rsa_private_key is None or self.rsa_public_key is None:
            self.rsa_private_key, self.rsa_public_key = generate_rsa_key()
            save_key(self.rsa_private_key, "rsa_private_key.pem")
            save_key(self.rsa_public_key, "rsa_public_key.pem")

    def check_password(self):
        password = "admin123"  # You can set this to a more secure password or retrieve it from a secure source
        attempts = 3
        while attempts > 0:
            user_input = simpledialog.askstring("Password", "Enter the password:", show='*')
            if user_input == password:
                self.create_widgets()
                break
            else:
                attempts -= 1
                messagebox.showerror("Error", f"Incorrect password. {attempts} attempts left.")
        else:
            messagebox.showerror("Error", "Access denied.")
            self.root.destroy()

    def create_widgets(self):
        self.style = ttk.Style()
        self.style.configure("TButton", font=("Helvetica", 12), padding=10)
        self.style.configure("TLabel", font=("Helvetica", 12), background="#1e1e1e", foreground="#ffffff")

        self.title_label = tk.Label(self.root, text="Text Encryption Tool", font=("Helvetica", 18, "bold"), bg="#1e1e1e", fg="#00ff00")
        self.title_label.pack(pady=10)

        self.method_var = tk.StringVar(value="AES")

        self.method_frame = tk.Frame(self.root, bg="#1e1e1e")
        self.method_frame.pack(pady=5)
        methods = [("AES", "AES"), ("DES", "DES"), ("RSA", "RSA")]
        for text, method in methods:
            rb = tk.Radiobutton(self.method_frame, text=text, variable=self.method_var, value=method, font=("Helvetica", 12), bg="#1e1e1e", fg="#ffffff", selectcolor="#2e2e2e", activebackground="#2e2e2e", activeforeground="#00ff00")
            rb.pack(side=tk.LEFT, padx=10)

        self.plaintext_label = ttk.Label(self.root, text="Plaintext")
        self.plaintext_label.pack(pady=5)
        self.plaintext_entry = tk.Entry(self.root, width=50, font=("Helvetica", 12))
        self.plaintext_entry.pack(pady=5)

        self.ciphertext_label = ttk.Label(self.root, text="Ciphertext")
        self.ciphertext_label.pack(pady=5)
        self.ciphertext_entry = tk.Entry(self.root, width=50, font=("Helvetica", 12))
        self.ciphertext_entry.pack(pady=5)

        self.button_frame = tk.Frame(self.root, bg="#1e1e1e")
        self.button_frame.pack(pady=20)
        self.encrypt_button = ttk.Button(self.button_frame, text="Encrypt", command=self.encrypt)
        self.encrypt_button.pack(side=tk.LEFT, padx=10)

        self.decrypt_button = ttk.Button(self.button_frame, text="Decrypt", command=self.decrypt)
        self.decrypt_button.pack(side=tk.LEFT, padx=10)

        self.save_key_button = ttk.Button(self.button_frame, text="Save Key", command=self.save_key_dialog)
        self.save_key_button.pack(side=tk.LEFT, padx=10)

        self.load_key_button = ttk.Button(self.button_frame, text="Load Key", command=self.load_key_dialog)
        self.load_key_button.pack(side=tk.LEFT, padx=10)

    def encrypt(self):
        method = self.method_var.get()
        plaintext = self.plaintext_entry.get()

        if method == "AES":
            encrypted_text = encrypt_aes(plaintext, self.aes_key)
        elif method == "DES":
            encrypted_text = encrypt_des(plaintext, self.des_key)
        elif method == "RSA":
            encrypted_text = encrypt_rsa(plaintext, self.rsa_public_key)
        else:
            messagebox.showerror("Error", "Invalid encryption method")
            return

        self.ciphertext_entry.delete(0, tk.END)
        self.ciphertext_entry.insert(0, encrypted_text)
        save_log("Encrypt", method, plaintext, encrypted_text)

    def decrypt(self):
        method = self.method_var.get()
        ciphertext = self.ciphertext_entry.get()

        try:
            if method == "AES":
                decrypted_text = decrypt_aes(ciphertext, self.aes_key)
            elif method == "DES":
                decrypted_text = decrypt_des(ciphertext, self.des_key)
            elif method == "RSA":
                decrypted_text = decrypt_rsa(ciphertext, self.rsa_private_key)
            else:
                messagebox.showerror("Error", "Invalid decryption method")
                return

            self.plaintext_entry.delete(0, tk.END)
            self.plaintext_entry.insert(0, decrypted_text)
            save_log("Decrypt", method, decrypted_text, ciphertext)
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")

    def save_key_dialog(self):
        method = self.method_var.get()
        if method == "AES":
            key = self.aes_key
            key_name = "aes_key.key"
        elif method == "DES":
            key = self.des_key
            key_name = "des_key.key"
        elif method == "RSA":
            key = self.rsa_private_key
            key_name = "rsa_private_key.pem"
            save_key(self.rsa_public_key, "rsa_public_key.pem")
        else:
            messagebox.showerror("Error", "Invalid encryption method")
            return

        save_key(key, key_name)
        messagebox.showinfo("Success", f"{method} key saved successfully")

    def load_key_dialog(self):
        method = self.method_var.get()
        try:
            if method == "AES":
                self.aes_key = load_key("aes_key.key")
            elif method == "DES":
                self.des_key = load_key("des_key.key")
            elif method == "RSA":
                self.rsa_private_key = load_key("rsa_private_key.pem")
                self.rsa_public_key = load_key("rsa_public_key.pem")
            else:
                messagebox.showerror("Error", "Invalid encryption method")
                return

            messagebox.showinfo("Success", f"{method} key loaded successfully")
        except Exception as e:
            messagebox.showerror("Error", f"Loading key failed: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionTool(root)
    root.mainloop()
