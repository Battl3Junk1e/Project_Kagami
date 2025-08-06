import customtkinter as ctk
from tkinter import messagebox
from PIL.Image import open as Image_open
import os
import sys
from hashlib import scrypt
from base64 import b64encode, b64decode
import json
from random import randint, choices, shuffle
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# --- Cross-platform app data directory utility ---
def get_appdata_dir():
    r"""
    Returns best directory for app data.
    Windows:   %LOCALAPPDATA%\ProjectKagami
    macOS:     ~/Library/Application Support/ProjectKagami
    Linux:     ~/.projectkagami
    """
    if sys.platform == "win32":
        base_dir = os.getenv('LOCALAPPDATA')
        if not base_dir:
            base_dir = os.path.expanduser('~\\AppData\\Local')
        appdata_dir = os.path.join(base_dir, 'ProjectKagami')
    elif sys.platform == "darwin":
        appdata_dir = os.path.expanduser('~/Library/Application Support/ProjectKagami')
    else:
        appdata_dir = os.path.expanduser('~/.projectkagami')
    os.makedirs(appdata_dir, exist_ok=True)
    return appdata_dir

APPDATA_DIR = get_appdata_dir()

class KagamiApp:
    N = 2 ** 14
    R = 8
    P = 1
    KEY_LEN = 64

    def __init__(self, root):
        self.root = root
        self.root.title("Project Kagami")
        self.window_width = 700
        self.window_height = 700
        self.screen_width = self.root.winfo_screenwidth()
        self.screen_height = self.root.winfo_screenheight()
        self.x = (self.screen_width // 2) - (self.window_width // 2)
        self.y = (self.screen_height // 2) - (self.window_height // 2)
        self.root.geometry(f"{self.window_width}x{self.window_height}+{self.x}+{self.y}")
        self.root.iconbitmap("kagami_icon_standard.ico")

        self.current_frame = None
        self.show_login_frame()

    # Now these paths point to the hidden appdata location!
    def master_key_path(self):
        return os.path.join(APPDATA_DIR, "master.kagami")

    def passwords_dat_path(self):
        return os.path.join(APPDATA_DIR, "passwords.kagami")

    def clear_current_frame(self):
        if self.current_frame is not None:
            self.current_frame.destroy()
            self.current_frame = None

    def show_login_frame(self):
        self.clear_current_frame()
        frame = ctk.CTkFrame(self.root, fg_color="#203354")
        frame.pack(fill="both", expand=True)
        self.current_frame = frame

        if os.path.exists("logo.webp"):
            logo_img = ctk.CTkImage(Image_open("logo.webp"), size=(300, 200))
            logo_label = ctk.CTkLabel(frame, image=logo_img, text="")
            logo_label.pack(pady=(50, 0))

        title = ctk.CTkLabel(frame, text="Project Kagami", font=("Segoe UI", 24, "bold"))
        title.pack(pady=(8, 8))
        subtitle = ctk.CTkLabel(frame, text="Please enter your master password", font=("Segoe UI", 14, "bold"))
        subtitle.pack(pady=(0, 20))

        self.password_input_login = ctk.CTkEntry(frame, show="*", width=240)
        self.password_input_login.pack(pady=6)
        self.password_input_login.bind("<Return>", lambda e: self.attempt_login())
        login_button = ctk.CTkButton(frame, text="Login", command=self.attempt_login)
        login_button.pack(pady=12)

        info = ctk.CTkLabel(frame, text="First login will save this as your master password.", font=("Segoe UI", 15, "italic", "bold"), text_color="#A9BCD0")
        info.pack(pady=(4, 0))

    def attempt_login(self):
        try:
            if not os.path.exists(self.master_key_path()):
                self.create_master_password(self.password_input_login.get())
            if not os.path.exists(self.passwords_dat_path()):
                with open(self.passwords_dat_path(), "w") as f:
                    f.write("[]")
            with open(self.master_key_path(), "r") as f:
                lines = f.readlines()
                salt = b64decode(lines[0].strip())
                hashed_pw = b64decode(lines[1].strip())
            input_password = self.password_input_login.get()
            key = scrypt(
                password=input_password.encode(),
                salt=salt,
                n=self.N,
                r=self.R,
                p=self.P,
                dklen=self.KEY_LEN
            )
            self.aes_key = key
            if key == hashed_pw:
                self.show_main_frame()
            else:
                messagebox.showerror("Incorrect password", "The password you have entered is not correct.")
        except Exception as e:
            messagebox.showerror("Error", f"Something went wrong: {e}")

    def create_master_password(self, password):
        salt = os.urandom(16)
        key = scrypt(
            password.encode(),
            salt=salt,
            n=self.N,
            r=self.R,
            p=self.P,
            dklen=self.KEY_LEN
        )
        with open(self.master_key_path(), "w") as f:
            f.write(f"{b64encode(salt).decode()}\n{b64encode(key).decode()}")

    def show_main_frame(self):
        self.clear_current_frame()
        frame = ctk.CTkFrame(self.root, fg_color="#1e2638")
        frame.pack(fill="both", expand=True)
        self.current_frame = frame

        title = ctk.CTkLabel(frame, text="Add a New Password", font=("Segoe UI", 18, "bold"))
        title.pack(pady=(150, 10))

        self.website_input = ctk.CTkEntry(frame, placeholder_text="Website", width=340)
        self.website_input.pack(pady=(0, 10))
        self.password_input = ctk.CTkEntry(frame, placeholder_text="Password", width=340)
        self.password_input.pack(pady=(0, 12))

        btn_frame = ctk.CTkFrame(frame, fg_color="transparent")
        btn_frame.pack(pady=(0, 12))
        generate_btn = ctk.CTkButton(btn_frame, text="Generate Password", command=self.generate_password, width=150)
        generate_btn.pack(side="left", padx=12)
        save_btn = ctk.CTkButton(btn_frame, text="Save", command=self.save_password_entry, width=100)
        save_btn.pack(side="left", padx=12)

        view_btn = ctk.CTkButton(frame, text="View Saved Passwords", command=self.show_view_passwords)
        view_btn.pack(pady=40)

        exit_btn = ctk.CTkButton(frame, text="Exit", fg_color="#243A5E", hover_color="#2C4C7B",
                                 command=self.root.destroy)
        exit_btn.pack(pady=10)

    def save_password_entry(self):
        website = self.website_input.get()
        password = self.password_input.get()
        if not website or not password:
            messagebox.showerror("Error", "You can't leave any fields empty.")
            return
        aesgcm = AESGCM(self.aes_key[:32])
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, password.encode(), None)
        entry = {
            "website": website,
            "nonce": b64encode(nonce).decode(),
            "ciphertext": b64encode(ciphertext).decode()
        }
        passwords_file = self.passwords_dat_path()
        if os.path.exists(passwords_file):
            with open(passwords_file, "r") as f:
                entries = json.load(f)
        else:
            entries = []
        entries.append(entry)
        with open(passwords_file, "w") as f:
            json.dump(entries, f, indent=4)
        messagebox.showinfo("Saved", f"Password for {website} has been saved successfully.")
        self.website_input.delete(0, ctk.END)
        self.password_input.delete(0, ctk.END)

    def generate_password(self):
        letters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
        numbers = '0123456789'
        symbols = '!#$%&()*+'
        rand_letters = randint(4, 8)
        rand_numbers = randint(4, 8)
        rand_symbols = randint(4, 8)
        chosen = choices(letters, k=rand_letters) + choices(numbers, k=rand_numbers) + choices(symbols, k=rand_symbols)
        shuffle(chosen)
        password = "".join(chosen)
        self.password_input.delete(0, ctk.END)
        self.password_input.insert(0, password)
        self.root.clipboard_clear()
        self.root.clipboard_append(password)
        self.root.update()

    def show_view_passwords(self):
        self.clear_current_frame()
        frame = ctk.CTkFrame(self.root, fg_color="#203354")
        frame.pack(fill="both", expand=True)
        self.current_frame = frame

        scroll_frame = ctk.CTkScrollableFrame(frame, width=600, height=500, fg_color="#18253c")
        scroll_frame.pack(pady=(10, 10), padx=10, fill="both", expand=True)

        btn_frame = ctk.CTkFrame(frame, fg_color="transparent")
        btn_frame.pack(fill="x", pady=12)

        back_btn = ctk.CTkButton(btn_frame, text="Back", command=self.show_main_frame)
        back_btn.pack(side="left", padx=20)
        exit_btn = ctk.CTkButton(btn_frame, text="Exit", fg_color="#243A5E", hover_color="#2C4C7B",
                                 command=self.root.destroy)
        exit_btn.pack(side="right", padx=20)

        # Load entries
        try:
            with open(self.passwords_dat_path(), "r") as f:
                entries = json.load(f)
            aesgcm = AESGCM(self.aes_key[:32])
            for idx, entry in enumerate(entries):
                website = entry["website"]
                nonce = b64decode(entry["nonce"])
                ciphertext = b64decode(entry["ciphertext"])
                try:
                    password = aesgcm.decrypt(nonce, ciphertext, None).decode()
                    display = f"{website}\n{password}"
                except Exception:
                    display = f"{website}\n[DECRYPTION FAILED]"

                entry_frame = ctk.CTkFrame(scroll_frame, fg_color="#22335A")
                entry_frame.pack(fill="x", pady=6, padx=6)

                entry_label = ctk.CTkLabel(entry_frame, text=display, font=("Segoe UI", 13), anchor="w", justify="left")
                entry_label.pack(side="left", padx=10, expand=True)

                del_btn = ctk.CTkButton(
                    entry_frame, text="Delete", fg_color="#3c4251", text_color="#cfd4e2",
                    width=80,
                    command=lambda i=idx: self.delete_password_entry(i)
                )
                del_btn.pack(side="right", padx=10)
                copy_btn = ctk.CTkButton(
                    entry_frame, text="Copy", fg_color="#3c4251", text_color="#cfd4e2",
                    width=80,
                    command=lambda i=idx: self.copy_password_entry(i)
                )
                copy_btn.pack(side="left", padx=10)
        except Exception as e:
            err_lbl = ctk.CTkLabel(scroll_frame, text=f"Failed to read password file: {e}", text_color="#ff8080")
            err_lbl.pack(pady=10)

    def copy_password_entry(self, index):
        try:
            with open(self.passwords_dat_path(), "r") as f:
                entries = json.load(f)
            if index < len(entries):
                entry = entries[index]
                nonce = b64decode(entry["nonce"])
                ciphertext = b64decode(entry["ciphertext"])
                aesgcm = AESGCM(self.aes_key[:32])
                try:
                    password = aesgcm.decrypt(nonce, ciphertext, None).decode()
                    self.root.clipboard_clear()
                    self.root.clipboard_append(password)
                    messagebox.showinfo("Copied", "Password copied to clipboard!")
                except Exception:
                    messagebox.showwarning("Error", "Decryption failed.")
            else:
                messagebox.showwarning("Invalid Index", "Selected entry does not exist.")
        except Exception as e:
            messagebox.showerror("Error", f"Could not copy password: {e}")

    def delete_password_entry(self, index):
        try:
            with open(self.passwords_dat_path(), "r") as f:
                content = f.read().strip()
                entries = json.loads(content) if content else []
            if index < len(entries):
                confirm = messagebox.askyesno("Confirm", "Are you sure you want to delete this entry?")
                if not confirm:
                    return
                del entries[index]
                with open(self.passwords_dat_path(), "w") as f:
                    json.dump(entries if entries else [], f, indent=4)
            self.show_view_passwords()
        except Exception as e:
            messagebox.showerror("Error", f"Could not delete: {e}")


if __name__ == "__main__":
    root = ctk.CTk()
    app = KagamiApp(root)
    root.mainloop()
