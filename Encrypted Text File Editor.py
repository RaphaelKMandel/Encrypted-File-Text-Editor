import os
import sys
import base64
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from tkinter import Tk, Toplevel, Frame, Label, Button, Checkbutton, Entry, Text, StringVar, Scrollbar, filedialog, messagebox, PhotoImage
from tkinter import BOTH, LEFT, RIGHT, TOP, BOTTOM, Y, END


args = sys.argv
FILEDIR = os.path.dirname(__file__)


def rgb2hex(r,g,b):
    return f"#{hex(r)[2:]}{hex(g)[2:]}{hex(b)[2:]}"
    

class PasswordEntry:               
    def __init__(self, password, mode):
        self.form = Toplevel()
        self.form.title("")
        self.form.geometry(f"200x100+{1920//2-100}+{1080//2-50}")
        self.form.attributes("-toolwindow", True)  # Windows Only
        self.form.protocol("WM_DELETE_WINDOW", self.destroy)  # Windows Only
        
        Label(self.form, text="Enter Password:").pack()
        self.password = StringVar(self.form)
        self.password.set(password)
        self.entry = Entry(self.form, textvariable=self.password)
        self.entry.pack()
        self.entry.bind("<Return>", lambda event: self.destroy())
        self.entry.bind("<FocusIn>", lambda event: self.entry.selection_range(0, END))
        self.entry.config(show="*")
        self.entry.focus()
        Button(self.form, text=mode, command=self.destroy).pack()
        self.textvar = StringVar()
        self.textvar.set("Show Password")
        Checkbutton(self.form, textvariable=self.textvar, command=self.toggle).pack()
        self.form.mainloop()
        
    def get_password(self):
        return self.password.get()

    def toggle(self):
        if self.textvar.get() == "Show Password":
            self.entry.config(show="")
            self.textvar.set("Hide Password")
        else:
            self.entry.config(show="*")
            self.textvar.set("Show Password")

    def destroy(self):
        self.form.destroy()
        self.form.quit()


class Editor:
    def __init__(self, root):
        self.scrollbar = Scrollbar(root)
        self.scrollbar.pack(side=RIGHT, fill=Y)
        self.editor = Text(root, width=400, height=450, yscrollcommand=self.scrollbar.set,
                           background=rgb2hex(230,230,230), fg='brown', undo=True, maxundo=-1)
        self.scrollbar.config(command=self.editor.yview)
        self.editor.pack(fill=BOTH)
        
    def clear(self):
        self.editor.delete(1.0, END)

    def insert(self, text):
        self.clear()
        self.editor.insert(END, text)

    def text(self):
        return bytes(self.editor.get(1.0, END), 'utf-8')


class App:       
    def __init__(self, file=None):
        self.window = Tk()
        self.window.geometry(f"1200x800+{1920//2-600}+{1080//2-400}")
        self.window.configure(bg=rgb2hex(200,200,200))
        self.window.iconphoto(False, PhotoImage(file=f"{FILEDIR}/icon.png"))
        
        self.window.bind("<Control-n>", lambda event: self.new())
        self.window.bind("<Control-o>", lambda event: self.open())
        self.window.bind("<Control-s>", lambda event: self.save())
        
        self.top = Frame(self.window)
        self.new_btn = Button(self.top, text='New', command=self.new)
        self.new_btn.grid(row=0, column=0)
        self.open_btn = Button(self.top, text='Open', command=self.open)
        self.open_btn.grid(row=0, column=1)
        self.save_btn = Button(self.top, text='Save', command=self.save)
        self.save_btn.grid(row=0, column=2)
        self.saveas_btn = Button(self.top, text='Save As', command=self.saveas)
        self.saveas_btn.grid(row=0, column=3)
        self.top.pack()
        self.editor = Editor(self.window)
        
        if file is not None:
            self.file = file
            self.password = ""
            self.load()
        else:
            self.new()

        self.window.mainloop()

    def new(self):
        self.editor.clear()
        self.file = None
        self.password = ""
        
    def open(self):
        self.new()
        file = filedialog.askopenfile(initialdir=FILEDIR, filetypes=[("Encrytped Text File", ".etf")])
        if file is not None:
            self.file = file.name
            self.load()

    def load(self):
        with open(self.file, 'rb') as f:
            text = f.read().strip().replace(b"\r", b"")  # Remove Extra Returns that Appear?
        self.editor.insert(text)
        decrypted_text = self.decrypt(text)
        if decrypted_text is not None:
            self.editor.insert(decrypted_text)
        else:
            self.new()
        
    def save(self):
        if self.file is None:
            self.saveas()
        else:
            text = self.editor.text()
            fernet = self.get_fernet(self.password)
            encrypted_text = fernet.encrypt(text)
            with open(self.file, 'wb') as f:
                f.write(encrypted_text)

    def saveas(self):
        file = filedialog.asksaveasfile(initialdir=FILEDIR, filetypes=[("Encrytped Text File", ".etf")], defaultextension='.etf')
        if file is not None:
            self.file = file.name
        else:
            return
            
        text = self.editor.text()
        self.password = PasswordEntry(self.password, "Encrypt").get_password()
        fernet = self.get_fernet(self.password)
        encrypted_text = fernet.encrypt(text)
        with open(self.file, 'wb') as f:
            f.write(encrypted_text)

    def decrypt(self, text):
        self.password = PasswordEntry(self.password, "Decrypt").get_password()
        fernet = self.get_fernet(self.password)
        return self.decryptable(fernet, text)
        
    def decryptable(self, fernet, text):
        try:
            decrypted_text = fernet.decrypt(text)
            return decrypted_text
        except InvalidToken:
            messagebox.showerror(title="Decryption Failed", message="Incorrect Password.")
            return None
            
    def get_fernet(self, password):
        kdf = PBKDF2HMAC(
                            algorithm=hashes.SHA256(),
                            length=32,
                            salt=b'\x1a*\xaf\xef\x01\xbb\xdf>\xcd,\xa1zC)\xbb\xfb',
                            iterations=390000,
                        )  
        key = base64.urlsafe_b64encode(kdf.derive(bytes(password, 'utf-8')))
        return Fernet(key)
        
    @property
    def file(self):
        return self._file
        
    @file.setter
    def file(self, file):
        self._file = file
        self.window.title(f"Arkie's Encrypted File Editor - {self.file}")


if __name__ == "__main__":
    file = None 
    if len(sys.argv) > 1:
        file = sys.argv[1]
    app = App(file)
