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

#Cross-platform app data directory
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

#Making sure images gets into the exe
def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller EXE """
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)

class KagamiApp:
    #Constants for encryption
    N = 2 ** 14
    R = 8
    P = 1
    KEY_LEN = 64
    #
    def __init__(self, root):
        self.root = root
        self.root.title("Project Kagami")
        self.window_width = 900
        self.window_height = 700
        self.screen_width = self.root.winfo_screenwidth()
        self.screen_height = self.root.winfo_screenheight()
        self.x = (self.screen_width // 2) - (self.window_width // 2)
        self.y = (self.screen_height // 2) - (self.window_height // 2)
        self.root.geometry(f"{self.window_width}x{self.window_height}+{self.x}+{self.y}")
        icon_path = resource_path("kagami_icon_standard.ico")
        self.root.iconbitmap(icon_path)


        self.current_frame = None
        self.show_login_frame()
    
    def master_key_path(self):
        return os.path.join(APPDATA_DIR, "master.kagami")

    def passwords_dat_path(self):
        return os.path.join(APPDATA_DIR, "passwords.kagami")
    #Destroys the active frame so the next screen can be shown seamlessly
    def clear_current_frame(self):
        if self.current_frame is not None:
            self.current_frame.destroy()
            self.current_frame = None
    #Creates the login frame
    def show_login_frame(self):
        self.clear_current_frame()
        frame = ctk.CTkFrame(self.root, fg_color="#203354")
        frame.pack(fill="both", expand=True)
        self.current_frame = frame
        logo_path = resource_path("logo.webp")
        if not os.path.exists(logo_path):
            messagebox.showerror("Error", f"Logo not found at {logo_path}")
        else:
            logo_img = ctk.CTkImage(Image_open(logo_path), size=(300, 200))
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

    #Logic for checking if the master password exists and is correct
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
    #Handles the creation of the master password
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
    #Creates the main menu frame
    def show_main_frame(self):
        self.clear_current_frame()
        frame = ctk.CTkFrame(self.root, fg_color="#1e2638")
        frame.pack(fill="both", expand=True)
        self.current_frame = frame


        title = ctk.CTkLabel(frame, text="Add a New Password", font=("Segoe UI", 18, "bold"))
        title.pack(pady=(150, 10))

        self.service_input = ctk.CTkEntry(frame, placeholder_text="Service", width=340)
        self.service_input.pack(pady=(0, 10))
        self.login_input = ctk.CTkEntry(frame, placeholder_text="Login", width=340)
        self.login_input.pack(pady=(0, 10))
        self.password_input = ctk.CTkEntry(frame, placeholder_text="Password", width=340)
        self.password_input.pack(pady=(0, 10))

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
        service = self.service_input.get()
        login = self.login_input.get()
        password = self.password_input.get()
        if not login or not password or not service:
            messagebox.showerror("Error", "You can't leave any fields empty.")
            return
        aesgcm = AESGCM(self.aes_key[:32])
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, password.encode(), None)
        entry = {
            "Service": service,
            "Login": login,
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
        messagebox.showinfo("Saved", f"Password for {service} has been saved successfully.")
        self.service_input.delete(0, ctk.END)
        self.login_input.delete(0, ctk.END)
        self.password_input.delete(0, ctk.END)


    #Generates a random password for the user and copies to clipboard
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
    #Creates the frame for the decrypted passwordlist
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
                service = entry["Service"]
                login = entry["Login"]
                nonce = b64decode(entry["nonce"])
                ciphertext = b64decode(entry["ciphertext"])
                try:
                    password = aesgcm.decrypt(nonce, ciphertext, None).decode()
                    display = f"{login}\n{password}"
                except Exception:
                    display = f"{login}\n[DECRYPTION FAILED]"

        

                entry_frame = ctk.CTkFrame(scroll_frame, fg_color="#22335A")
                entry_frame.pack(fill="x", pady=6, padx=6)

                #Spacing
                entry_frame.grid_columnconfigure(4, weight=1) 

                # service (right aligned in fixed-width col)
                service_label = ctk.CTkLabel(entry_frame, text=service, font=("Segoe UI", 13), anchor="w", justify="left", width=140)
                service_label.grid(row=0, column=1, sticky="e", padx=(10,0))

                # spacer between service and login
                spacer_service = ctk.CTkFrame(entry_frame, width=100, height=1, fg_color="transparent")
                spacer_service.grid(row=0, column=2)

                # login + password (left aligned, starts at same pixel every row)
                login_info = ctk.CTkLabel(entry_frame, text=display, font=("Segoe UI", 13), anchor="w", justify="left")
                login_info.grid(row=0, column=3, sticky="w")

                # buttons on right
                copy_btn = ctk.CTkButton(entry_frame, text="Copy", width=80, fg_color="#3c4251", text_color="#cfd4e2")
                copy_btn.grid(row=0, column=5, padx=(10,6), sticky="e")

                del_btn = ctk.CTkButton(entry_frame, text="Delete", width=80, fg_color="#3c4251", text_color="#cfd4e2", command=lambda i=idx: self.delete_password_entry(i))
                del_btn.grid(row=0, column=6, padx=(0,10), sticky="e")

        except Exception as e:
            err_lbl = ctk.CTkLabel(scroll_frame, text=f"Failed to read password file: {e}", text_color="#ff8080")
            err_lbl.pack(pady=10)
    #Copies the selected password to the clipboard
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
    #Logic to delete passwords
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
