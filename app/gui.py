"""Tkinter user interface for the JWT client."""
from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, ttk
from typing import Iterable

from .auth import AuthService, EnvironmentConfig, DEFAULT_ENVIRONMENTS


class AuthApp(tk.Tk):
    """Main window displaying the authentication form."""

    def __init__(
        self,
        auth_service: AuthService | None = None,
        environments: Iterable[EnvironmentConfig] | None = None,
    ) -> None:
        super().__init__()
        self.title("Client JWT")
        self.minsize(500, 320)
        self.configure(padx=16, pady=16)

        envs = tuple(environments) if environments else DEFAULT_ENVIRONMENTS
        self._auth_service = auth_service or AuthService(envs)
        self._environments = envs

        self._client_id_var = tk.StringVar()
        self._client_secret_var = tk.StringVar()
        self._environment_var = tk.StringVar(value=self._environments[0].name)

        self._build_widgets()

    def _build_widgets(self) -> None:
        form = ttk.Frame(self)
        form.grid(column=0, row=0, sticky="nsew")
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)

        ttk.Label(form, text="Client ID").grid(column=0, row=0, sticky="w", pady=(0, 4))
        client_id_entry = ttk.Entry(form, textvariable=self._client_id_var)
        client_id_entry.grid(column=0, row=1, sticky="ew", pady=(0, 8))
        client_id_entry.focus()

        ttk.Label(form, text="Client Secret").grid(
            column=0, row=2, sticky="w", pady=(0, 4)
        )
        secret_entry = ttk.Entry(form, textvariable=self._client_secret_var, show="•")
        secret_entry.grid(column=0, row=3, sticky="ew", pady=(0, 8))

        ttk.Label(form, text="Environnement").grid(
            column=0, row=4, sticky="w", pady=(0, 4)
        )
        env_combo = ttk.Combobox(
            form,
            textvariable=self._environment_var,
            values=[env.name for env in self._environments],
            state="readonly",
        )
        env_combo.grid(column=0, row=5, sticky="ew", pady=(0, 8))
        env_combo.bind("<<ComboboxSelected>>", self._on_environment_change)

        submit_btn = ttk.Button(
            form,
            text="Obtenir un JWT",
            command=self._on_request_token,
        )
        submit_btn.grid(column=0, row=6, sticky="ew", pady=(8, 0))

        form.columnconfigure(0, weight=1)

        result_label = ttk.Label(self, text="Jeton JWT :")
        result_label.grid(column=0, row=1, sticky="sw", pady=(16, 4))

        self._result_text = tk.Text(self, height=6, wrap="word")
        self._result_text.grid(column=0, row=2, sticky="nsew")
        self._result_text.configure(state="disabled")

        copy_btn = ttk.Button(self, text="Copier", command=self._copy_to_clipboard)
        copy_btn.grid(column=0, row=3, sticky="e", pady=(8, 0))

        self.rowconfigure(2, weight=1)

    def _on_environment_change(self, event: tk.Event[object]) -> None:  # pragma: no cover
        event.widget.selection_clear()

    def _on_request_token(self) -> None:
        try:
            token = self._auth_service.obtain_jwt(
                self._client_id_var.get().strip(),
                self._client_secret_var.get(),
                self._environment_var.get(),
            )
        except KeyError:
            messagebox.showerror(
                "Environnement inconnu",
                "L'environnement sélectionné n'est pas configuré.",
            )
            return
        except ValueError as exc:
            messagebox.showwarning("Champs manquants", str(exc))
            return

        self._display_token(token)
        messagebox.showinfo("Succès", "Le jeton JWT a été généré avec succès.")

    def _display_token(self, token: str) -> None:
        self._result_text.configure(state="normal")
        self._result_text.delete("1.0", tk.END)
        self._result_text.insert(tk.END, token)
        self._result_text.configure(state="disabled")

    def _copy_to_clipboard(self) -> None:
        token = self._result_text.get("1.0", tk.END).strip()
        if not token:
            messagebox.showwarning(
                "Aucun jeton",
                "Générez d'abord un jeton avant de le copier.",
            )
            return
        self.clipboard_clear()
        self.clipboard_append(token)
        messagebox.showinfo("Copié", "Le jeton JWT a été copié dans le presse-papiers.")


def main() -> None:
    """Launch the authentication application."""

    app = AuthApp()
    app.mainloop()


if __name__ == "__main__":
    main()
