import os
import tkinter as tk
from tkinter import filedialog, messagebox
from ttkbootstrap.constants import SUCCESS, PRIMARY, WARNING, INVERSE
from ttkbootstrap import Style, ttk

from key_gen import generate_and_save_keypair
from encrypt import encrypt_file as encrypt
from decrypt import decrypt_file as decrypt

# --- Setup Directories ---
os.makedirs("keys", exist_ok=True)
os.makedirs("outputs", exist_ok=True)

# --- Core Functions ---

def set_status(message):
    status_var.set(message)
    root.update_idletasks()

def generate_keys():
    set_status("Generating keys...")
    try:
        generate_and_save_keypair()
        messagebox.showinfo("Success", "Keys generated in 'keys/' folder.")
        set_status("Key generation completed.")
    except Exception as e:
        messagebox.showerror("Error", f"Key generation failed:\n{str(e)}")
        set_status("Error during key generation.")

def encrypt_file():
    plaintext_path = filedialog.askopenfilename(title="Select Plaintext File", initialdir="./")
    public_key_path = filedialog.askopenfilename(
        title="Select Public Key File", initialdir="keys/",filetypes=[("Public Key Files", "*.txt")])
    
    if plaintext_path and public_key_path:
        set_status("Encrypting file...")
        try:
            output_path = filedialog.asksaveasfilename(
                title="Save Encrypted File As", initialdir="outputs/",
                defaultextension=".bin",
                filetypes=[("Binary Files", "*.bin")]
            )
            if not output_path:
                return
            encrypt(plaintext_path, public_key_path, output_path)
            messagebox.showinfo("Success", f"Encryption complete!\nSaved to {output_path}")
            set_status("Encryption completed.")
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed:\n{str(e)}")
            set_status("Error during encryption.")

def decrypt_file():
    ciphertext_path = filedialog.askopenfilename(
        title="Select Ciphertext File",
        initialdir="outputs/,",
        filetypes=[("Binary Files", "*.bin")]
    )
    private_key_path = filedialog.askopenfilename(
        title="Select Private Key File",
        initialdir="keys/",
        filetypes=[("Private Key Files", "*.txt")]
    )
    
    if ciphertext_path and private_key_path:
        output_path = filedialog.asksaveasfilename(title="Save Decrypted File As", initialdir="outputs/")
        if not output_path:
            return
        
        set_status("Decrypting file...")
        try:
            decrypt(ciphertext_path, private_key_path, output_path)
            messagebox.showinfo("Success", f"Decryption complete!\nSaved to {output_path}")
            set_status("Decryption completed.")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed:\n{str(e)}")
            set_status("Error during decryption.")

# --- Centering Window ---

def center_window(win, width, height):
    screen_width = win.winfo_screenwidth()
    screen_height = win.winfo_screenheight()
    x = int((screen_width/2) - (width/2))
    y = int((screen_height/2) - (height/2))
    win.geometry(f'{width}x{height}+{x}+{y}')

# --- Main Window ---

# Apply Dark Theme
style = Style(theme="darkly")

root = style.master
root.title("RSA-OAEP Encryption App")
center_window(root, 600, 400)

# Create a Notebook (Tabs)
tab_control = ttk.Notebook(root)

# Create each tab frame
tab_generate = ttk.Frame(tab_control)
tab_encrypt = ttk.Frame(tab_control)
tab_decrypt = ttk.Frame(tab_control)

tab_control.add(tab_generate, text='🔑 Generate Key')
tab_control.add(tab_encrypt, text='🔒 Encrypt')
tab_control.add(tab_decrypt, text='🔓 Decrypt')

tab_control.pack(expand=1, fill='both', padx=10, pady=10)

# --- Generate Key Tab ---
generate_label = ttk.Label(tab_generate, text="Generate 2048-bit RSA Key Pair", font=("Helvetica", 16))
generate_label.pack(pady=30)

generate_button = ttk.Button(tab_generate, text="Generate Keys", command=generate_keys, style=SUCCESS)
generate_button.pack(pady=10)

# --- Encrypt Tab ---
encrypt_label = ttk.Label(tab_encrypt, text="Encrypt a File", font=("Helvetica", 16))
encrypt_label.pack(pady=30)

encrypt_button = ttk.Button(tab_encrypt, text="Select Files and Encrypt", command=encrypt_file, style=PRIMARY)
encrypt_button.pack(pady=10)

# --- Decrypt Tab ---
decrypt_label = ttk.Label(tab_decrypt, text="Decrypt a File", font=("Helvetica", 16))
decrypt_label.pack(pady=30)

decrypt_button = ttk.Button(tab_decrypt, text="Select Files and Decrypt", command=decrypt_file, style=WARNING)
decrypt_button.pack(pady=10)

# --- Status Bar ---
status_var = tk.StringVar()
status_var.set("Ready")

status_bar = ttk.Label(root, textvariable=status_var, anchor='w', relief='sunken', style=INVERSE)
status_bar.pack(side='bottom', fill='x')

root.mainloop()
