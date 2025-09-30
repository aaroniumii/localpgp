"""Punto de entrada para la aplicación LocalPGP."""

import tkinter as tk

from localpgp.ui import EncryptorApp


def main() -> None:
    root = tk.Tk()
    EncryptorApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
