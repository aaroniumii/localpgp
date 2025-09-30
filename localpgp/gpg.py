"""Herramientas de interacción con GnuPG."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Iterable, List, Optional, Sequence, Tuple


@dataclass(frozen=True)
class KeyInfo:
    """Información básica de una clave pública."""

    fingerprint: str
    uid: str

    @property
    def display(self) -> str:
        """Representación amigable para UI."""

        return self.uid or self.fingerprint


class GPGHandler:
    """Encapsula todas las interacciones con ``gpg``."""

    def __init__(self, gpg_binary: str = "gpg") -> None:
        self.gpg_binary = gpg_binary

    # ------------------------------------------------------------------
    # Utilidades internas
    # ------------------------------------------------------------------
    def _run(self, args: Sequence[str], stdin: Optional[bytes] = None) -> subprocess.CompletedProcess:
        """Ejecuta ``gpg`` devolviendo siempre un ``CompletedProcess``."""

        try:
            return subprocess.run(args, input=stdin, capture_output=True, check=False)
        except FileNotFoundError:
            return subprocess.CompletedProcess(args=args, returncode=127, stdout=b"", stderr=b"gpg not found")

    @staticmethod
    def _recipient_args(recipients: Iterable[str]) -> List[str]:
        args: List[str] = []
        for recipient in recipients:
            args.extend(["--recipient", recipient])
        return args

    # ------------------------------------------------------------------
    # Consultas
    # ------------------------------------------------------------------
    def list_keys(self) -> List[KeyInfo]:
        """Devuelve las claves públicas disponibles."""

        process = self._run([self.gpg_binary, "--list-keys", "--with-colons"])
        keys: List[KeyInfo] = []
        fingerprint: Optional[str] = None
        for raw_line in process.stdout.decode(errors="replace").splitlines():
            parts = raw_line.split(":")
            if not parts:
                continue
            tag = parts[0]
            if tag == "fpr":
                fingerprint = parts[9]
            elif tag == "uid" and fingerprint:
                uid = parts[9]
                keys.append(KeyInfo(fingerprint=fingerprint, uid=uid))
                fingerprint = None
        return keys

    # ------------------------------------------------------------------
    # Operaciones con texto
    # ------------------------------------------------------------------
    def encrypt_text(
        self,
        text: str,
        recipients: Sequence[str],
        signing_fpr: Optional[str],
        passphrase: Optional[str],
    ) -> Tuple[int, str, str]:
        args = [
            self.gpg_binary,
            "--batch",
            "--yes",
            "--trust-model",
            "always",
            "--pinentry-mode",
            "loopback",
            "--armor",
            "--encrypt",
        ]
        if signing_fpr:
            args.extend(["--sign", "--default-key", signing_fpr])
        args.extend(self._recipient_args(recipients))

        if signing_fpr and passphrase is not None:
            args.extend(["--passphrase", passphrase])

        process = self._run(args, stdin=text.encode())
        return (
            process.returncode,
            process.stdout.decode(errors="replace"),
            process.stderr.decode(errors="replace"),
        )

    def decrypt_text(self, armored: str, passphrase: Optional[str]) -> Tuple[int, str, str]:
        args = [
            self.gpg_binary,
            "--batch",
            "--yes",
            "--trust-model",
            "always",
            "--pinentry-mode",
            "loopback",
            "--decrypt",
        ]
        if passphrase is not None:
            args.extend(["--passphrase", passphrase])

        process = self._run(args, stdin=armored.encode())
        return (
            process.returncode,
            process.stdout.decode(errors="replace"),
            process.stderr.decode(errors="replace"),
        )

    def sign_text(
        self,
        text: str,
        signing_fpr: str,
        passphrase: Optional[str],
        clearsign: bool = True,
    ) -> Tuple[int, str, str]:
        args = [
            self.gpg_binary,
            "--batch",
            "--yes",
            "--pinentry-mode",
            "loopback",
            "--armor",
            "--default-key",
            signing_fpr,
        ]

        if clearsign:
            args.append("--clearsign")
        else:
            args.append("--sign")

        if passphrase is not None:
            args.extend(["--passphrase", passphrase])

        process = self._run(args, stdin=text.encode())
        return (
            process.returncode,
            process.stdout.decode(errors="replace"),
            process.stderr.decode(errors="replace"),
        )

    def verify_text(self, signed_text: str) -> Tuple[int, str, str]:
        args = [
            self.gpg_binary,
            "--batch",
            "--yes",
            "--trust-model",
            "always",
            "--pinentry-mode",
            "loopback",
            "--decrypt",
        ]

        process = self._run(args, stdin=signed_text.encode())
        return (
            process.returncode,
            process.stdout.decode(errors="replace"),
            process.stderr.decode(errors="replace"),
        )

    # ------------------------------------------------------------------
    # Operaciones con archivos
    # ------------------------------------------------------------------
    def encrypt_file(
        self,
        src_path: str,
        dst_path: str,
        recipients: Sequence[str],
        signing_fpr: Optional[str],
        passphrase: Optional[str],
    ) -> Tuple[int, str]:
        args: List[str] = [
            self.gpg_binary,
            "--batch",
            "--yes",
            "--trust-model",
            "always",
            "--pinentry-mode",
            "loopback",
            "--encrypt",
            "-o",
            dst_path,
            src_path,
        ]

        if signing_fpr:
            args[args.index("--encrypt") + 1 : args.index("-o")] = ["--encrypt", "--sign", "--default-key", signing_fpr]
        insert_pos = args.index(src_path)
        args[insert_pos:insert_pos] = self._recipient_args(recipients)

        if signing_fpr and passphrase is not None:
            out_index = args.index("-o")
            args[out_index:out_index] = ["--passphrase", passphrase]

        process = self._run(args)
        return process.returncode, process.stderr.decode(errors="replace")

    def decrypt_file(self, src_path: str, dst_path: str, passphrase: Optional[str]) -> Tuple[int, str]:
        args = [
            self.gpg_binary,
            "--batch",
            "--yes",
            "--trust-model",
            "always",
            "--pinentry-mode",
            "loopback",
            "--decrypt",
        ]
        if passphrase is not None:
            args.extend(["--passphrase", passphrase])
        args.extend(["-o", dst_path, src_path])

        process = self._run(args)
        return process.returncode, process.stderr.decode(errors="replace")

    def sign_file(
        self,
        src_path: str,
        dst_path: str,
        signing_fpr: str,
        passphrase: Optional[str],
        detach: bool = True,
    ) -> Tuple[int, str]:
        args: List[str] = [
            self.gpg_binary,
            "--batch",
            "--yes",
            "--pinentry-mode",
            "loopback",
            "--armor",
            "--default-key",
            signing_fpr,
            "-o",
            dst_path,
        ]

        if detach:
            args.append("--detach-sign")
        else:
            args.append("--sign")

        if passphrase is not None:
            args.extend(["--passphrase", passphrase])

        args.append(src_path)

        process = self._run(args)
        return process.returncode, process.stderr.decode(errors="replace")

    def verify_file(self, signature_path: str, data_path: Optional[str] = None) -> Tuple[int, str]:
        args = [
            self.gpg_binary,
            "--batch",
            "--yes",
            "--pinentry-mode",
            "loopback",
            "--verify",
            signature_path,
        ]
        if data_path is not None:
            args.append(data_path)

        process = self._run(args)
        return process.returncode, process.stderr.decode(errors="replace")


__all__ = ["GPGHandler", "KeyInfo"]
