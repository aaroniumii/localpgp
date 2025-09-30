"""Aplicación gráfica para gestionar operaciones PGP."""

from __future__ import annotations

import os
import queue
import subprocess
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from tkinter import ttk

from ..gpg import GPGHandler, KeyInfo


@dataclass
class RecipientSelection:
    """Mantiene la relación entre la etiqueta mostrada y el fingerprint."""

    display: str
    fingerprint: str
    variable: tk.BooleanVar


@dataclass
class AppState:
    gpg: GPGHandler
    keys: List[KeyInfo] = field(default_factory=list)
    directory: Optional[Path] = None
    delete_original: bool = True


class EncryptorApp:
    """Ventana principal de la aplicación."""

    def __init__(self, root: tk.Tk, gpg: Optional[GPGHandler] = None) -> None:
        self.root = root
        self.root.title("LocalPGP")
        self.state = AppState(gpg=gpg or GPGHandler())

        self._op_thread: Optional[threading.Thread] = None
        self._queue: "queue.Queue[Tuple[str, str]]" = queue.Queue()
        self._log_max_lines = 300

        self._init_variables()
        self._build_layout()
        self._load_keys_into_ui()
        self._poll_queue()

    # ------------------------------------------------------------------
    # Inicialización
    # ------------------------------------------------------------------
    def _init_variables(self) -> None:
        self.state.keys = self.state.gpg.list_keys()
        displays = [key.display for key in self.state.keys]
        default_display = displays[0] if displays else "(sin claves)"

        self.signing_key_var = tk.StringVar(value=default_display)
        self.delete_original_var = tk.BooleanVar(value=self.state.delete_original)
        self.directory_var = tk.StringVar(value="")
        self.recipient_vars: List[RecipientSelection] = []

    def _build_layout(self) -> None:
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

        style = ttk.Style()
        style.theme_use("clam")

        self.main_frame = ttk.Frame(self.root, padding=12)
        self.main_frame.grid(row=0, column=0, sticky="nsew")
        self.main_frame.columnconfigure(1, weight=1)
        self.main_frame.rowconfigure(1, weight=1)

        self._build_sidebar()
        self._build_notebook()
        self._build_status_bar()
        self._build_log_output()

    def _build_sidebar(self) -> None:
        sidebar = ttk.Frame(self.main_frame, padding=(0, 0, 12, 0))
        sidebar.grid(row=0, column=0, rowspan=2, sticky="nsw")
        sidebar.columnconfigure(0, weight=1)

        # Clave de firma
        key_frame = ttk.LabelFrame(sidebar, text="Clave de firma")
        key_frame.grid(row=0, column=0, sticky="ew", pady=(0, 12))
        key_frame.columnconfigure(0, weight=1)

        self.signing_key_combo = ttk.Combobox(
            key_frame,
            textvariable=self.signing_key_var,
            state="readonly",
            values=[],
        )
        self.signing_key_combo.grid(row=0, column=0, padx=8, pady=8, sticky="ew")

        # Destinatarios
        recipients_frame = ttk.LabelFrame(sidebar, text="Destinatarios")
        recipients_frame.grid(row=1, column=0, sticky="nsew", pady=(0, 12))
        recipients_frame.columnconfigure(0, weight=1)
        recipients_frame.rowconfigure(0, weight=1)

        self.recipient_container = ttk.Frame(recipients_frame)
        self.recipient_container.grid(row=0, column=0, sticky="nsew")
        recipients_frame.rowconfigure(0, weight=1)

        recipient_scroll = ttk.Scrollbar(recipients_frame, orient="vertical")
        recipient_scroll.grid(row=0, column=1, sticky="ns")

        self.recipient_container.columnconfigure(0, weight=1)
        self.recipient_container.rowconfigure(0, weight=1)

        self.recipient_canvas = tk.Canvas(
            self.recipient_container,
            borderwidth=0,
            highlightthickness=0,
            width=220,
        )
        self.recipient_canvas.grid(row=0, column=0, sticky="nsew")
        self.recipient_canvas.configure(yscrollcommand=recipient_scroll.set)
        recipient_scroll.configure(command=self.recipient_canvas.yview)

        self.recipient_inner = ttk.Frame(self.recipient_canvas)
        self.recipient_canvas.create_window((0, 0), window=self.recipient_inner, anchor="nw")
        self.recipient_inner.bind("<Configure>", lambda e: self.recipient_canvas.configure(scrollregion=self.recipient_canvas.bbox("all")))

        # Opciones
        options_frame = ttk.LabelFrame(sidebar, text="Opciones")
        options_frame.grid(row=2, column=0, sticky="ew")
        options_frame.columnconfigure(0, weight=1)

        delete_check = ttk.Checkbutton(
            options_frame,
            text="Eliminar originales tras cifrar",
            variable=self.delete_original_var,
        )
        delete_check.grid(row=0, column=0, padx=8, pady=8, sticky="w")

        import_button = ttk.Button(options_frame, text="Importar clave pública", command=self.import_public_key)
        import_button.grid(row=1, column=0, padx=8, pady=(0, 8), sticky="ew")

    def _build_notebook(self) -> None:
        notebook = ttk.Notebook(self.main_frame)
        notebook.grid(row=0, column=1, sticky="nsew")
        self.main_frame.rowconfigure(0, weight=1)
        self.main_frame.columnconfigure(1, weight=1)

        # Pestaña de archivos
        files_frame = ttk.Frame(notebook, padding=12)
        files_frame.columnconfigure(1, weight=1)
        files_frame.rowconfigure(3, weight=1)
        notebook.add(files_frame, text="Archivos")

        ttk.Label(files_frame, text="Directorio de trabajo:").grid(row=0, column=0, sticky="w")

        dir_entry = ttk.Entry(files_frame, textvariable=self.directory_var)
        dir_entry.grid(row=1, column=0, columnspan=2, sticky="ew", pady=4)

        browse_button = ttk.Button(files_frame, text="Seleccionar...", command=self.select_directory)
        browse_button.grid(row=1, column=2, sticky="ew", padx=(8, 0))

        self.encrypt_dir_button = ttk.Button(files_frame, text="Cifrar directorio", command=self.encrypt_files)
        self.encrypt_dir_button.grid(row=2, column=0, sticky="ew", pady=(12, 0))

        self.decrypt_dir_button = ttk.Button(files_frame, text="Descifrar directorio", command=self.decrypt_files)
        self.decrypt_dir_button.grid(row=2, column=1, sticky="ew", pady=(12, 0))

        files_frame.columnconfigure(0, weight=1)
        files_frame.columnconfigure(1, weight=1)

        # Pestaña de texto
        text_frame = ttk.Frame(notebook, padding=12)
        text_frame.columnconfigure(0, weight=1)
        text_frame.columnconfigure(1, weight=1)
        text_frame.rowconfigure(1, weight=1)
        text_frame.rowconfigure(4, weight=1)
        notebook.add(text_frame, text="Texto")

        ttk.Label(text_frame, text="Texto a cifrar:").grid(row=0, column=0, sticky="w")
        self.text_input = tk.Text(text_frame, height=8, wrap="word")
        self.text_input.grid(row=1, column=0, columnspan=3, sticky="nsew", pady=(0, 8))

        encrypt_text_button = ttk.Button(text_frame, text="Cifrar texto", command=self.encrypt_text)
        encrypt_text_button.grid(row=2, column=0, sticky="ew")

        decrypt_text_button = ttk.Button(text_frame, text="Descifrar texto", command=self.decrypt_text)
        decrypt_text_button.grid(row=2, column=1, sticky="ew")

        clear_button = ttk.Button(text_frame, text="Limpiar campos", command=self.clear_text_fields)
        clear_button.grid(row=2, column=2, sticky="ew")

        ttk.Label(text_frame, text="Resultado cifrado:").grid(row=3, column=0, sticky="w")
        self.encrypted_output = tk.Text(text_frame, height=8, wrap="word")
        self.encrypted_output.grid(row=4, column=0, columnspan=3, sticky="nsew", pady=(0, 8))

        copy_encrypted = ttk.Button(
            text_frame,
            text="Copiar cifrado",
            command=lambda: self.copy_to_clipboard(self.encrypted_output.get("1.0", tk.END).strip()),
        )
        copy_encrypted.grid(row=5, column=0, sticky="ew", pady=(0, 8))

        ttk.Label(text_frame, text="Resultado descifrado:").grid(row=6, column=0, sticky="w")
        self.decrypted_output = tk.Text(text_frame, height=6, wrap="word")
        self.decrypted_output.grid(row=7, column=0, columnspan=3, sticky="nsew")

        copy_decrypted = ttk.Button(
            text_frame,
            text="Copiar texto",
            command=lambda: self.copy_to_clipboard(self.decrypted_output.get("1.0", tk.END).strip()),
        )
        copy_decrypted.grid(row=8, column=0, sticky="ew", pady=(8, 0))

    def _build_status_bar(self) -> None:
        status_frame = ttk.Frame(self.main_frame, padding=(0, 12, 0, 0))
        status_frame.grid(row=1, column=1, sticky="ew")
        status_frame.columnconfigure(0, weight=1)

        self.progress = ttk.Progressbar(status_frame, orient="horizontal", mode="determinate")
        self.progress.grid(row=0, column=0, sticky="ew")

        self.status_label = ttk.Label(status_frame, text="Estado: inactivo")
        self.status_label.grid(row=1, column=0, sticky="w", pady=(4, 0))

    def _build_log_output(self) -> None:
        log_frame = ttk.LabelFrame(self.main_frame, text="Registro")
        log_frame.grid(row=2, column=0, columnspan=2, sticky="nsew", pady=(12, 0))
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)

        self.log_output = tk.Text(log_frame, height=10, state=tk.DISABLED, wrap="word")
        self.log_output.grid(row=0, column=0, sticky="nsew")

        scrollbar = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_output.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.log_output.configure(yscrollcommand=scrollbar.set)

    def _load_keys_into_ui(self) -> None:
        displays = [key.display for key in self.state.keys]
        if not displays:
            displays = ["(sin claves)"]
        self.signing_key_combo.configure(values=displays)
        self.signing_key_var.set(displays[0])

        for child in self.recipient_inner.winfo_children():
            child.destroy()
        self.recipient_vars.clear()

        for index, key in enumerate(self.state.keys):
            var = tk.BooleanVar(value=False)
            chk = ttk.Checkbutton(self.recipient_inner, text=key.display, variable=var)
            chk.grid(row=index, column=0, sticky="w", padx=4, pady=2)
            self.recipient_vars.append(RecipientSelection(display=key.display, fingerprint=key.fingerprint, variable=var))

        self._update_buttons_state()

    # ------------------------------------------------------------------
    # Utilidades
    # ------------------------------------------------------------------
    def _update_buttons_state(self) -> None:
        has_keys = bool(self.state.keys)
        self.encrypt_dir_button.configure(state=tk.NORMAL if has_keys else tk.DISABLED)
        # Se permite descifrar aunque no haya claves
        self.decrypt_dir_button.configure(state=tk.NORMAL)

    def _poll_queue(self) -> None:
        try:
            while True:
                kind, payload = self._queue.get_nowait()
                if kind == "log":
                    self._append_log(payload)
                elif kind == "status":
                    self.status_label.configure(text=payload)
                elif kind == "progress_max":
                    self.progress.configure(maximum=max(int(payload), 1), value=0)
                elif kind == "progress_step":
                    self.progress.step(1)
        except queue.Empty:
            pass
        finally:
            self.root.after(120, self._poll_queue)

    def _append_log(self, message: str) -> None:
        self.log_output.configure(state=tk.NORMAL)
        content = self.log_output.get("1.0", tk.END).splitlines()
        content.append(message)
        if len(content) > self._log_max_lines:
            content = content[-self._log_max_lines :]
        self.log_output.delete("1.0", tk.END)
        self.log_output.insert(tk.END, "\n".join(content) + "\n")
        self.log_output.see(tk.END)
        self.log_output.configure(state=tk.DISABLED)

    def _get_selected_recipients(self) -> List[str]:
        recipients = [item.fingerprint for item in self.recipient_vars if item.variable.get()]
        return recipients

    def _require_thread(self, target, *args) -> None:
        if self._op_thread and self._op_thread.is_alive():
            messagebox.showwarning("Operación en curso", "Espere a que finalice la operación actual.")
            return
        self._op_thread = threading.Thread(target=target, args=args, daemon=True)
        self._op_thread.start()

    def _ask_passphrase(self, prompt: str) -> Optional[str]:
        return simpledialog.askstring("Passphrase", prompt, show="*")

    def _ask_directory(self) -> Optional[Path]:
        selected = filedialog.askdirectory()
        return Path(selected) if selected else None

    def copy_to_clipboard(self, text: str) -> None:
        if not text:
            messagebox.showinfo("Portapapeles", "No hay texto para copiar.")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        messagebox.showinfo("Portapapeles", "Texto copiado correctamente.")

    def clear_text_fields(self) -> None:
        self.text_input.delete("1.0", tk.END)
        self.encrypted_output.delete("1.0", tk.END)
        self.decrypted_output.delete("1.0", tk.END)

    # ------------------------------------------------------------------
    # Eventos de UI
    # ------------------------------------------------------------------
    def select_directory(self) -> None:
        directory = self._ask_directory()
        if directory:
            self.state.directory = directory
            self.directory_var.set(str(directory))

    def encrypt_files(self) -> None:
        recipients = self._get_selected_recipients()
        if not recipients:
            messagebox.showerror("Sin destinatarios", "Seleccione al menos un destinatario.")
            return
        if not self.state.directory:
            messagebox.showerror("Sin directorio", "Seleccione un directorio primero.")
            return

        signing_fpr = self._selected_signing_fingerprint()
        passphrase = None
        if signing_fpr:
            passphrase = self._ask_passphrase("Introduce la passphrase para firmar:")
            if passphrase is None:
                return

        if self.delete_original_var.get():
            confirm = messagebox.askyesno("Confirmar", "¿Eliminar los archivos originales tras cifrar?")
            if not confirm:
                return

        self._require_thread(self._encrypt_directory_worker, recipients, signing_fpr, passphrase)

    def decrypt_files(self) -> None:
        if not self.state.directory:
            messagebox.showerror("Sin directorio", "Seleccione un directorio primero.")
            return
        passphrase = self._ask_passphrase("Introduce la passphrase para descifrar:")
        if passphrase is None:
            return
        self._require_thread(self._decrypt_directory_worker, passphrase)

    def encrypt_text(self) -> None:
        text = self.text_input.get("1.0", tk.END).strip()
        if not text:
            messagebox.showerror("Sin texto", "Introduce texto a cifrar.")
            return
        recipients = self._get_selected_recipients()
        if not recipients:
            messagebox.showerror("Sin destinatarios", "Seleccione al menos un destinatario.")
            return

        signing_fpr = self._selected_signing_fingerprint()
        passphrase = None
        if signing_fpr:
            passphrase = self._ask_passphrase("Introduce la passphrase para firmar:")
            if passphrase is None:
                return

        self._set_status("Estado: cifrando texto...", indeterminate=True)
        code, out, err = self.state.gpg.encrypt_text(text, recipients, signing_fpr, passphrase)
        self._set_status("Estado: inactivo", indeterminate=False)
        if code == 0 and out:
            self.encrypted_output.delete("1.0", tk.END)
            self.encrypted_output.insert(tk.END, out)
            self._append_log(f"Texto cifrado para {', '.join(recipients)}")
        else:
            self._append_log(f"Error al cifrar texto: {err.strip() or 'desconocido'}")
            messagebox.showerror("Error", "No se pudo cifrar el texto. Consulta el registro para más detalles.")

    def decrypt_text(self) -> None:
        armored = self.encrypted_output.get("1.0", tk.END).strip()
        if not armored:
            messagebox.showerror("Sin datos", "Introduce texto cifrado a descifrar.")
            return
        passphrase = self._ask_passphrase("Introduce la passphrase para descifrar:")
        if passphrase is None:
            return

        self._set_status("Estado: descifrando texto...", indeterminate=True)
        code, out, err = self.state.gpg.decrypt_text(armored, passphrase)
        self._set_status("Estado: inactivo", indeterminate=False)
        if code == 0:
            self.decrypted_output.delete("1.0", tk.END)
            self.decrypted_output.insert(tk.END, out)
            self._append_log("Texto descifrado correctamente")
        else:
            self._append_log(f"Error al descifrar texto: {err.strip() or 'desconocido'}")
            messagebox.showerror("Error", "No se pudo descifrar el texto. Consulta el registro para más detalles.")

    def import_public_key(self) -> None:
        file_path = filedialog.askopenfilename(
            title="Selecciona un archivo de clave pública",
            filetypes=[
                ("Claves públicas", "*.asc *.gpg *.pgp"),
                ("Todos los archivos", "*.*"),
            ],
        )
        if not file_path:
            return
        self._set_status("Estado: importando clave...", indeterminate=True)
        result = subprocess.run(
            ["gpg", "--import", file_path],
            capture_output=True,
        )
        self._set_status("Estado: inactivo", indeterminate=False)
        if result.returncode == 0:
            messagebox.showinfo("Importación", "Clave importada correctamente.")
            self.state.keys = self.state.gpg.list_keys()
            self._load_keys_into_ui()
        else:
            error = result.stderr.decode(errors="replace").strip() or result.stdout.decode(errors="replace").strip()
            self._append_log(f"Error al importar clave: {error}")
            messagebox.showerror("Importación", "No se pudo importar la clave. Consulta el registro.")

    # ------------------------------------------------------------------
    # Helpers de estado
    # ------------------------------------------------------------------
    def _set_status(self, message: str, *, indeterminate: bool) -> None:
        self.status_label.configure(text=message)
        if indeterminate:
            self.progress.configure(mode="indeterminate")
            self.progress.start(10)
        else:
            self.progress.stop()
            self.progress.configure(mode="determinate")
            self.progress.configure(value=0)

    def _selected_signing_fingerprint(self) -> Optional[str]:
        display = self.signing_key_var.get()
        for key in self.state.keys:
            if key.display == display:
                return key.fingerprint
        return None

    # ------------------------------------------------------------------
    # Trabajadores en segundo plano
    # ------------------------------------------------------------------
    def _encrypt_directory_worker(self, recipients: Sequence[str], signing_fpr: Optional[str], passphrase: Optional[str]) -> None:
        self._queue.put(("status", "Estado: cifrando archivos..."))
        directory = self.state.directory
        if directory is None:
            self._queue.put(("status", "Estado: inactivo"))
            return

        files: List[Path] = []
        for root_dir, _, filenames in os.walk(directory):
            for filename in filenames:
                if not filename.endswith(".gpg"):
                    files.append(Path(root_dir) / filename)

        self._queue.put(("progress_max", str(len(files) or 1)))

        for path in files:
            out_path = path.with_suffix(path.suffix + ".gpg")
            code, err = self.state.gpg.encrypt_file(str(path), str(out_path), recipients, signing_fpr, passphrase)
            if code == 0:
                self._queue.put(("log", f"Cifrado: {path} → {out_path}"))
                if self.delete_original_var.get():
                    try:
                        path.unlink()
                        self._queue.put(("log", f"Eliminado original: {path}"))
                    except OSError as exc:
                        self._queue.put(("log", f"No se pudo eliminar {path}: {exc}"))
            else:
                self._queue.put(("log", f"Error cifrando {path}: {err.strip()}"))
            self._queue.put(("progress_step", "1"))

        self._queue.put(("status", "Estado: cifrado finalizado"))

    def _decrypt_directory_worker(self, passphrase: str) -> None:
        self._queue.put(("status", "Estado: descifrando archivos..."))
        directory = self.state.directory
        if directory is None:
            self._queue.put(("status", "Estado: inactivo"))
            return

        files: List[Path] = []
        for root_dir, _, filenames in os.walk(directory):
            for filename in filenames:
                if filename.endswith(".gpg"):
                    files.append(Path(root_dir) / filename)

        self._queue.put(("progress_max", str(len(files) or 1)))

        for path in files:
            out_path = path.with_suffix("")
            code, err = self.state.gpg.decrypt_file(str(path), str(out_path), passphrase)
            if code == 0:
                self._queue.put(("log", f"Descifrado: {path} → {out_path}"))
                try:
                    path.unlink()
                    self._queue.put(("log", f"Eliminado cifrado: {path}"))
                except OSError as exc:
                    self._queue.put(("log", f"No se pudo eliminar {path}: {exc}"))
            else:
                self._queue.put(("log", f"Error descifrando {path}: {err.strip()}"))
            self._queue.put(("progress_step", "1"))

        self._queue.put(("status", "Estado: descifrado finalizado"))


__all__ = ["EncryptorApp"]
