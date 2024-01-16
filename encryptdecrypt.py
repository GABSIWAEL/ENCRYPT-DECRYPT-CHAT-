import tkinter as tk
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
        # --------------------------------------------
        # the DES dosen't work when you choose DES it generate an error 
        # -------------------------------------------


class ChatApplication:
    def __init__(self, master):
        self.master = master
        master.title("Simple Chat Application")

        # Key variables
        self.algorithm_var = tk.StringVar()
        self.key_var = tk.StringVar()

        # GUI components
        self.text_output = tk.Text(
            master, height=15, width=50, state=tk.DISABLED)
        self.text_input = tk.Entry(master, width=50)
        self.algorithm_label = tk.Label(master, text="Encryption Algorithm:")
        self.algorithm_option = tk.OptionMenu(
            master, self.algorithm_var, "AES", "DES")  # Add more options as needed
        self.key_label = tk.Label(master, text="Key:")
        self.key_entry = tk.Entry(master, width=50, textvariable=self.key_var)
        self.encrypt_button = tk.Button(
            master, text="Encrypt", command=self.encrypt_message)
        self.decrypt_button = tk.Button(
            master, text="Decrypt", command=self.decrypt_message)

        # Place GUI components
        self.text_output.grid(row=0, column=0, columnspan=2)
        self.text_input.grid(row=1, column=0)
        self.algorithm_label.grid(row=2, column=0, sticky="w", padx=5)
        self.algorithm_option.grid(row=2, column=1, sticky="ew", padx=5)
        self.key_label.grid(row=3, column=0, sticky="w", padx=5)
        self.key_entry.grid(row=3, column=1, sticky="ew", padx=5)
        self.encrypt_button.grid(row=4, column=1, sticky="ew", pady=5)
        self.decrypt_button.grid(row=5, column=1, sticky="ew")

    def generate_key_and_iv(self, password):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            salt=b'salt',
            iterations=100000,
            length=32 + 16,  # 32 bytes for key and 16 bytes for IV
            backend=default_backend()
        )
        key_and_iv = kdf.derive(password.encode())
        return key_and_iv[:32], key_and_iv[32:]

    def encrypt_message(self):
        message = self.text_input.get()
        algorithm = self.algorithm_var.get()
        key = self.key_var.get()

        if not key:
            self.display_message("Please enter a key.")
            return

        key, iv = self.generate_key_and_iv(key)

        # Choose the encryption algorithm dynamically
        if algorithm == 'AES':
            cipher = Cipher(algorithms.AES(key), modes.CFB(iv),
                            backend=default_backend())
        elif algorithm == 'DES':
            cipher = Cipher(algorithms.DES(key), modes.CFB(iv),
                            backend=default_backend())
        else:
            # Add more encryption algorithms as needed
            self.display_message("Unsupported encryption algorithm")
            return

        encryptor = cipher.encryptor()

        # Encrypt the message
        ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
        encrypted_message = base64.urlsafe_b64encode(iv + ciphertext).decode()

        self.display_message(f"You (Encrypted): {encrypted_message}")

    def decrypt_message(self):
        ciphertext = self.text_input.get()
        algorithm = self.algorithm_var.get()
        key = self.key_var.get()

        if not key:
            self.display_message("Please enter a key.")
            return

        # Decode the ciphertext and extract IV
        try:
            data = base64.urlsafe_b64decode(ciphertext.encode())
            iv = data[:16]
            ciphertext = data[16:]
        except:
            self.display_message("Invalid ciphertext format")
            return

        key, _ = self.generate_key_and_iv(key)

        # Choose the decryption algorithm dynamically
        if algorithm == 'AES':
            cipher = Cipher(algorithms.AES(key), modes.CFB(iv),
                            backend=default_backend())
        elif algorithm == 'DES':
            cipher = Cipher(algorithms.DES(key), modes.CFB(iv),
                            backend=default_backend())
        else:
            # Add more decryption algorithms as needed
            self.display_message("Unsupported decryption algorithm")
            return

        decryptor = cipher.decryptor()

        # Decrypt the message
        try:
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            self.display_message(f"Friend (Decrypted): {plaintext.decode()}")
        except:
            self.display_message(
                "Decryption error. Check the key and algorithm.")

    def display_message(self, message):
        self.text_output.config(state=tk.NORMAL)
        self.text_output.insert(tk.END, message + "\n")
        self.text_output.config(state=tk.DISABLED)


if __name__ == "__main__":
    root = tk.Tk()
    app = ChatApplication(root)
    root.mainloop()
