import os
import sys
import threading
import queue
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from tkinter.ttk import Progressbar
import subprocess
from typing import List, Tuple, Optional, Dict


# -----------------------------
# GPG Interaction Layer
# -----------------------------
class GPGHandler:
    """Encapsula todas las llamadas a gpg de forma segura y multiplataforma."""

    def __init__(self) -> None:
        self.gpg_bin = "gpg"

    def _run(self, args: List[str], stdin: Optional[bytes] = None) -> subprocess.CompletedProcess:
        """Ejecuta gpg devolviendo CompletedProcess. No lanza excepción."""
        try:
            return subprocess.run(
                args,
                input=stdin,
                capture_output=True,
                check=False,
            )
        except FileNotFoundError:
            cp = subprocess.CompletedProcess(args=args, returncode=127, stdout=b"", stderr=b"gpg not found")
            return cp

    # ---- Claves ----
    def list_keys(self) -> List[Dict[str, str]]:
        """
        Devuelve una lista de dicts con información mínima de claves públicas:
        [{"fpr": fingerprint, "uid": uid_string}]
        """
        cp = self._run([self.gpg_bin, "--list-keys", "--with-colons"])
        keys: List[Dict[str, str]] = []
        current_fpr = None
        for line in cp.stdout.decode(errors="replace").splitlines():
            parts = line.split(":")
            if not parts:
                continue
            tag = parts[0]
            if tag == "fpr":
                current_fpr = parts[9]
            elif tag == "uid" and current_fpr:
                uid = parts[9]
                keys.append({"fpr": current_fpr, "uid": uid})
                current_fpr = None
        return keys

    # ---- Construcción de argumentos comunes ----
    def _recipient_args(self, recipients: List[str]) -> List[str]:
        args: List[str] = []
        for r in recipients:
            args.extend(["--recipient", r])
        return args

    # ---- Texto ----
    def encrypt_text(self, text: str, recipients: List[str], signing_fpr: Optional[str], passphrase: Optional[str]) -> Tuple[int, str, str]:
        args = [
            self.gpg_bin,
            "--batch",
            "--yes",
            "--trust-model", "always",
            "--pinentry-mode", "loopback",
            "--armor",
            "--encrypt",
        ]
        if signing_fpr:
            args.extend(["--sign", "--default-key", signing_fpr])
        args.extend(self._recipient_args(recipients))
        # Usar passphrase por stdin si hay firma
        stdin_data: Optional[bytes] = None
        if signing_fpr and passphrase is not None:
            args.extend(["--passphrase-fd", "0"])  # leer passphrase de stdin
            stdin_data = passphrase.encode()
        # El texto va después de la passphrase si existe
        payload = (stdin_data or b"") + text.encode()
        cp = self._run(args, stdin=payload)
        return cp.returncode, cp.stdout.decode(errors="replace"), cp.stderr.decode(errors="replace")

    def decrypt_text(self, armored: str, passphrase: Optional[str]) -> Tuple[int, str, str]:
        args = [
            self.gpg_bin,
            "--batch",
            "--yes",
            "--trust-model", "always",
            "--pinentry-mode", "loopback",
            "--decrypt",
            "--passphrase-fd", "0",
        ]
        stdin_data = (passphrase or "").encode() + armored.encode()
        cp = self._run(args, stdin=stdin_data)
        return cp.returncode, cp.stdout.decode(errors="replace"), cp.stderr.decode(errors="replace")

    # ---- Archivos ----
    def encrypt_file(self, src_path: str, dst_path: str, recipients: List[str], signing_fpr: Optional[str], passphrase: Optional[str]) -> Tuple[int, str]:
        args = [
            self.gpg_bin,
            "--batch",
            "--yes",
            "--trust-model", "always",
            "--pinentry-mode", "loopback",
            "--encrypt",
            "-o", dst_path,
            src_path,
        ]
        if signing_fpr:
            args[args.index("--encrypt")+1:args.index("-o")] = ["--encrypt", "--sign", "--default-key", signing_fpr]
        args[args.index(src_path):args.index(src_path)] = self._recipient_args(recipients)

        stdin_data = None
        if signing_fpr and passphrase is not None:
            # insertar --passphrase-fd 0 antes del -o
            insert_idx = args.index("-o")
            args[insert_idx:insert_idx] = ["--passphrase-fd", "0"]
            stdin_data = passphrase.encode()
        cp = self._run(args, stdin=stdin_data)
        return cp.returncode, cp.stderr.decode(errors="replace")

    def decrypt_file(self, src_path: str, dst_path: str, passphrase: Optional[str]) -> Tuple[int, str]:
        args = [
            self.gpg_bin,
            "--batch",
            "--yes",
            "--trust-model", "always",
            "--pinentry-mode", "loopback",
            "--decrypt",
            "-o", dst_path,
            src_path,
            "--passphrase-fd", "0",
        ]
        cp = self._run(args, stdin=(passphrase or "").encode())
        return cp.returncode, cp.stderr.decode(errors="replace")


# -----------------------------
# Tkinter App
# -----------------------------
class EncryptorApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("File & Text Encryptor/Decryptor")
        self.gpg = GPGHandler()
        self._op_thread: Optional[threading.Thread] = None
        self._queue: "queue.Queue[Tuple[str, str]]" = queue.Queue()
        self._log_max_lines = 300

        self.initialize_variables()
        self.create_widgets()
        self.configure_grid()
        self.poll_queue()

    # ---------- State ----------
    def initialize_variables(self) -> None:
        self.keys = self.gpg.list_keys()
        self.directory_path = ""
        self.signing_key_var = tk.StringVar(self.root)
        self.delete_original_var = tk.BooleanVar(value=True)
        # mapping para OptionMenu: mostrar uid, guardar fpr
        display_values = [k["uid"] for k in self.keys] if self.keys else []
        default_display = display_values[0] if display_values else "(sin claves)"
        self.signing_key_var.set(default_display)
        self._display_to_fpr = {k["uid"]: k["fpr"] for k in self.keys}

    # ---------- UI ----------
    def create_widgets(self) -> None:
        self.create_directory_selection()
        self.create_key_selection()
        self.create_recipient_selection()
        self.create_delete_option()
        self.create_text_encryption_widgets()
        self.create_log_output()
        self.create_import_key_button()
        self.create_status_bar()
        self.update_buttons_state()

    def configure_grid(self) -> None:
        for c in range(3):
            self.root.grid_columnconfigure(c, weight=1)
        for r in range(12):
            self.root.grid_rowconfigure(r, weight=0)
        self.root.grid_rowconfigure(11, weight=1)

    def create_directory_selection(self) -> None:
        self.select_button = tk.Button(self.root, text="Select Directory", command=self.select_directory)
        self.select_button.grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.encrypt_dir_button = tk.Button(self.root, text="Encrypt Directory", command=self.encrypt_files)
        self.encrypt_dir_button.grid(row=0, column=1, padx=5, pady=5)
        self.decrypt_dir_button = tk.Button(self.root, text="Decrypt Directory", command=self.decrypt_files)
        self.decrypt_dir_button.grid(row=0, column=2, padx=5, pady=5)
        self.dir_label = tk.Label(self.root, text="(no directory)")
        self.dir_label.grid(row=1, column=0, columnspan=3, padx=5, pady=2, sticky="w")

    def create_key_selection(self) -> None:
        self.signing_key_label = tk.Label(self.root, text="Signing Key:")
        self.signing_key_label.grid(row=2, column=0, padx=5, pady=5, sticky="w")
        options = list(self._display_to_fpr.keys()) or ["(sin claves)"]
        self.signing_key_menu = tk.OptionMenu(self.root, self.signing_key_var, *options)
        self.signing_key_menu.grid(row=2, column=1, columnspan=2, padx=5, pady=5, sticky="ew")

    def create_recipient_selection(self) -> None:
        self.recipient_label = tk.Label(self.root, text="Recipients:")
        self.recipient_label.grid(row=3, column=0, padx=5, pady=5, sticky="nw")
        self.recipient_frame = tk.Frame(self.root, borderwidth=1, relief="groove")
        self.recipient_frame.grid(row=3, column=1, columnspan=2, padx=5, pady=5, sticky="nsew")
        self.recipient_vars: List[Tuple[str, tk.BooleanVar]] = []
        for k in self.keys:
            var = tk.BooleanVar()
            chk = tk.Checkbutton(self.recipient_frame, text=k["uid"], variable=var)
            chk.pack(anchor='w')
            self.recipient_vars.append((k["uid"], var))

    def create_delete_option(self) -> None:
        self.delete_original_check = tk.Checkbutton(
            self.root,
            text="Delete original files after encryption",
            variable=self.delete_original_var,
        )
        self.delete_original_check.grid(row=4, column=0, columnspan=3, padx=5, pady=5, sticky="w")

    def create_text_encryption_widgets(self) -> None:
        self.text_input_label = tk.Label(self.root, text="Texto:")
        self.text_input_label.grid(row=5, column=0, padx=5, pady=5, sticky="w")
        self.text_input = tk.Text(self.root, height=6, width=60)
        self.text_input.grid(row=5, column=1, columnspan=2, padx=5, pady=5, sticky="nsew")
        self.encrypt_text_button = tk.Button(self.root, text="Encrypt Text", command=self.encrypt_text)
        self.encrypt_text_button.grid(row=6, column=0, padx=5, pady=5)
        self.decrypt_text_button = tk.Button(self.root, text="Decrypt Text", command=self.decrypt_text)
        self.decrypt_text_button.grid(row=6, column=1, padx=5, pady=5)
        self.copy_encrypted_button = tk.Button(self.root, text="Copy Encrypted", command=lambda: self.copy_to_clipboard(self.encrypted_text_output.get("1.0", tk.END).strip()))
        self.copy_encrypted_button.grid(row=7, column=0, padx=5, pady=5)
        self.encrypted_text_output = tk.Text(self.root, height=6, width=60)
        self.encrypted_text_output.grid(row=7, column=1, columnspan=2, padx=5, pady=5, sticky="nsew")
        self.copy_decrypted_button = tk.Button(self.root, text="Copy Decrypted", command=lambda: self.copy_to_clipboard(self.decrypted_text_output.get("1.0", tk.END).strip()))
        self.copy_decrypted_button.grid(row=8, column=0, padx=5, pady=5)
        self.decrypted_text_output = tk.Text(self.root, height=6, width=60)
        self.decrypted_text_output.grid(row=8, column=1, columnspan=2, padx=5, pady=5, sticky="nsew")
        self.clear_button = tk.Button(self.root, text="Clear Fields", command=self.clear_text_fields)
        self.clear_button.grid(row=9, column=0, columnspan=3, padx=5, pady=5)

    def create_import_key_button(self) -> None:
        self.import_key_button = tk.Button(self.root, text="Import Public Key", command=self.import_public_key)
        self.import_key_button.grid(row=10, column=0, padx=5, pady=5, sticky="w")

    def create_status_bar(self) -> None:
        self.progress = Progressbar(self.root, orient=tk.HORIZONTAL, length=200, mode='determinate')
        self.progress.grid(row=10, column=1, columnspan=2, padx=5, pady=5, sticky="ew")
        self.status_label = tk.Label(self.root, text="Status: Idle")
        self.status_label.grid(row=11, column=0, columnspan=3, padx=5, pady=5, sticky="w")

    def create_log_output(self) -> None:
        self.log_output = tk.Text(self.root, height=12, width=80, state=tk.DISABLED)
        self.log_output.grid(row=12, column=0, columnspan=3, padx=5, pady=5, sticky="nsew")

    # ---------- Helpers UI ----------
    def update_buttons_state(self) -> None:
        has_keys = bool(self.keys)
        self.encrypt_dir_button.configure(state=tk.NORMAL if has_keys else tk.DISABLED)
        self.decrypt_dir_button.configure(state=tk.NORMAL)

    def select_directory(self) -> None:
        self.directory_path = filedialog.askdirectory()
        if self.directory_path:
            self.dir_label.config(text=self.directory_path)

    def get_selected_recipients(self) -> List[str]:
        selected_uids = [uid for uid, var in self.recipient_vars if var.get()]
        # Mapear de uid mostrado a fpr, si no existe usar el uid directamente
        mapped = [self._display_to_fpr.get(uid, uid) for uid in selected_uids]
        return mapped

    def request_passphrase(self, prompt: str = "Enter your passphrase:") -> Optional[str]:
        return simpledialog.askstring("Passphrase", prompt, show='*')

    def update_log(self, message: str) -> None:
        self.log_output.config(state=tk.NORMAL)
        # Limitar líneas
        content = self.log_output.get("1.0", tk.END).splitlines()
        content.append(message)
        if len(content) > self._log_max_lines:
            content = content[-self._log_max_lines:]
        self.log_output.delete("1.0", tk.END)
        self.log_output.insert(tk.END, "\n".join(content) + "\n")
        self.log_output.see(tk.END)
        self.log_output.config(state=tk.DISABLED)

    def copy_to_clipboard(self, text: str) -> None:
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        messagebox.showinfo("Success", "Text copied to clipboard.")

    def clear_text_fields(self) -> None:
        self.text_input.delete("1.0", tk.END)
        self.encrypted_text_output.delete("1.0", tk.END)
        self.decrypted_text_output.delete("1.0", tk.END)

    # ---------- Threads / Queue ----------
    def poll_queue(self) -> None:
        try:
            while True:
                kind, payload = self._queue.get_nowait()
                if kind == "log":
                    self.update_log(payload)
                elif kind == "status":
                    self.status_label.config(text=payload)
                elif kind == "progress_max":
                    self.progress.config(maximum=int(payload))
                    self.progress['value'] = 0
                elif kind == "progress_step":
                    self.progress['value'] = min(self.progress['value'] + 1, self.progress['maximum'])
        except queue.Empty:
            pass
        finally:
            self.root.after(100, self.poll_queue)

    def _run_in_thread(self, target, *args) -> None:
        if self._op_thread and self._op_thread.is_alive():
            messagebox.showwarning("Busy", "Another operation is running.")
            return
        self._op_thread = threading.Thread(target=target, args=args, daemon=True)
        self._op_thread.start()

    # ---------- Directory Ops ----------
    def encrypt_files(self) -> None:
        recipients = self.get_selected_recipients()
        if not recipients:
            messagebox.showerror("Error", "Please select at least one recipient.")
            return
        if not self.directory_path:
            messagebox.showerror("Error", "Please select a directory first.")
            return
        signing_display = self.signing_key_var.get()
        signing_fpr = self._display_to_fpr.get(signing_display)
        passphrase = None
        if signing_fpr:
            passphrase = self.request_passphrase("Enter your passphrase (for signing):")
            if passphrase is None:
                return
        if self.delete_original_var.get():
            if not messagebox.askyesno("Confirm", "Delete original files after successful encryption?"):
                return
        self._run_in_thread(self._encrypt_files_worker, recipients, signing_fpr, passphrase)

    def _encrypt_files_worker(self, recipients: List[str], signing_fpr: Optional[str], passphrase: Optional[str]) -> None:
        self._queue.put(("status", "Status: Encrypting..."))
        files: List[str] = []
        for root_dir, _, filenames in os.walk(self.directory_path):
            for fn in filenames:
                if not fn.endswith('.gpg'):
                    files.append(os.path.join(root_dir, fn))
        self._queue.put(("progress_max", str(max(1, len(files)))))

        for path in files:
            out_path = path + ".gpg"
            rc, err = self.gpg.encrypt_file(path, out_path, recipients, signing_fpr, passphrase)
            if rc == 0:
                self._queue.put(("log", f"Encrypted: {path} -> {out_path}"))
                if self.delete_original_var.get():
                    try:
                        os.remove(path)
                        self._queue.put(("log", f"Deleted original: {path}"))
                    except OSError as e:
                        self._queue.put(("log", f"Delete failed: {path} ({e})"))
            else:
                self._queue.put(("log", f"ERROR encrypting {path}: {err.strip()}"))
            self._queue.put(("progress_step", "1"))

        self._queue.put(("status", "Status: Encryption completed!"))

    def decrypt_files(self) -> None:
        if not self.directory_path:
            messagebox.showerror("Error", "Please select a directory first.")
            return
        passphrase = self.request_passphrase("Enter your passphrase to decrypt:")
        if passphrase is None:
            return
        self._run_in_thread(self._decrypt_files_worker, passphrase)

    def _decrypt_files_worker(self, passphrase: str) -> None:
        self._queue.put(("status", "Status: Decrypting..."))
        files: List[str] = []
        for root_dir, _, filenames in os.walk(self.directory_path):
            for fn in filenames:
                if fn.endswith('.gpg'):
                    files.append(os.path.join(root_dir, fn))
        self._queue.put(("progress_max", str(max(1, len(files)))))

        for path in files:
            out_path = os.path.splitext(path)[0]
            rc, err = self.gpg.decrypt_file(path, out_path, passphrase)
            if rc == 0:
                self._queue.put(("log", f"Decrypted: {path} -> {out_path}"))
                try:
                    os.remove(path)
                    self._queue.put(("log", f"Removed encrypted file: {path}"))
                except OSError as e:
                    self._queue.put(("log", f"Could not remove {path}: {e}"))
            else:
                self._queue.put(("log", f"ERROR decrypting {path}: {err.strip()}"))
            self._queue.put(("progress_step", "1"))

        self._queue.put(("status", "Status: Decryption completed!"))

    # ---------- Text Ops ----------
    def encrypt_text(self) -> None:
        text = self.text_input.get("1.0", tk.END).strip()
        if not text:
            messagebox.showerror("Error", "Please enter text to encrypt.")
            return
        recipients = self.get_selected_recipients()
        if not recipients:
            messagebox.showerror("Error", "Please select at least one recipient.")
            return
        signing_display = self.signing_key_var.get()
        signing_fpr = self._display_to_fpr.get(signing_display)
        passphrase = None
        if signing_fpr:
            passphrase = self.request_passphrase("Enter your passphrase (for signing):")
            if passphrase is None:
                return
        self.status_label.config(text="Status: Encrypting...")
        self.progress.config(mode='indeterminate')
        self.progress.start(10)
        rc, out, err = self.gpg.encrypt_text(text, recipients, signing_fpr, passphrase)
        self.progress.stop()
        self.progress.config(mode='determinate')
        if rc == 0 and out:
            self.encrypted_text_output.delete("1.0", tk.END)
            self.encrypted_text_output.insert(tk.END, out)
            self.update_log(f"Text encrypted successfully for recipients: {', '.join(recipients)}")
            self.status_label.config(text="Status: Encryption completed!")
        else:
            self.status_label.config(text="Status: Encryption failed!")
            self.update_log(f"Error encrypting text: {err.strip() or 'unknown error'}")

    def decrypt_text(self) -> None:
        armored = self.encrypted_text_output.get("1.0", tk.END).strip()
        if not armored:
            messagebox.showerror("Error", "Please enter encrypted text to decrypt.")
            return
        passphrase = self.request_passphrase("Enter your passphrase to decrypt:")
        if passphrase is None:
            return
        self.status_label.config(text="Status: Decrypting...")
        self.progress.config(mode='indeterminate')
        self.progress.start(10)
        rc, out, err = self.gpg.decrypt_text(armored, passphrase)
        self.progress.stop()
        self.progress.config(mode='determinate')
        if rc == 0:
            self.decrypted_text_output.delete("1.0", tk.END)
            self.decrypted_text_output.insert(tk.END, out)
            self.update_log("Text decrypted successfully")
            self.status_label.config(text="Status: Decryption completed!")
        else:
            self.status_label.config(text="Status: Decryption failed!")
            self.update_log(f"Error decrypting text: {err.strip() or 'unknown error'}")

    # ---------- Keys ----------
    def import_public_key(self) -> None:
        file_path = filedialog.askopenfilename(
            title="Select Public Key File",
            filetypes=[
                ("Public Key Files", "*.asc *.gpg *.pgp"),
                ("All Files", "*.*"),
            ],
        )
        if not file_path:
            return
        self.status_label.config(text="Status: Importing key...")
        cp = subprocess.run(["gpg", "--import", file_path], capture_output=True)
        if cp.returncode == 0:
            messagebox.showinfo("Success", "Public key imported successfully!")
            # recargar claves
            self.keys = self.gpg.list_keys()
            self._display_to_fpr = {k["uid"]: k["fpr"] for k in self.keys}
            self.signing_key_var.set(list(self._display_to_fpr.keys())[0] if self._display_to_fpr else "(sin claves)")
            self.update_recipient_menu()
            self.update_buttons_state()
            self.status_label.config(text="Status: Idle")
        else:
            self.status_label.config(text="Status: Import failed!")
            self.update_log(f"Error importing public key: {cp.stderr.decode(errors='replace').strip()}")

    def update_recipient_menu(self) -> None:
        for widget in self.recipient_frame.winfo_children():
            widget.destroy()
        self.recipient_vars.clear()
        for k in self.keys:
            var = tk.BooleanVar()
            chk = tk.Checkbutton(self.recipient_frame, text=k["uid"], variable=var)
            chk.pack(anchor='w')
            self.recipient_vars.append((k["uid"], var))


if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptorApp(root)
    root.mainloop()

