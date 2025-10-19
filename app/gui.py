"""Tkinter user interface for the JWT client."""
from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, ttk
from typing import Iterable, Protocol, Callable
import requests

from app.auth import (
    AuthService,
    CMXService,
    EnvironmentConfig,
    DEFAULT_ENVIRONMENTS,
    is_jwt_valid
)


class ProfileFrame(ttk.Frame):
    """Frame pour la saisie du profil et du DocStore ID."""
    
    def __init__(
        self,
        parent: tk.Widget,
        on_back: Callable[[], None],
        current_jwt: str,
        environment: EnvironmentConfig,
    ) -> None:
        super().__init__(parent)
        self._on_back = on_back
        self._current_jwt = current_jwt
        self._environment = environment
        self._cmx_service = CMXService(environment)
        
        self._profile_var = tk.StringVar()
        self._enduser_var = tk.StringVar()
        self._docstore_id_var = tk.StringVar()
        
        self._build_widgets()
        
    def _build_widgets(self) -> None:
        # Titre
        title_label = ttk.Label(
            self,
            text="Configuration du profil",
            font=("TkDefaultFont", 12, "bold")
        )
        title_label.grid(column=0, row=0, sticky="w", pady=(0, 16))
        
        # Formulaire
        form = ttk.Frame(self)
        form.grid(column=0, row=1, sticky="nsew")
        
        # Champ Profil
        ttk.Label(form, text="CMX Profile").grid(column=0, row=0, sticky="w", pady=(0, 4))
        profile_entry = ttk.Entry(form, textvariable=self._profile_var)
        profile_entry.grid(column=0, row=1, sticky="ew", pady=(0, 8))
        profile_entry.focus()
        
        # Champ CMX Enduser
        ttk.Label(form, text="CMX Enduser").grid(column=0, row=2, sticky="w", pady=(0, 4))
        enduser_entry = ttk.Entry(form, textvariable=self._enduser_var)
        enduser_entry.grid(column=0, row=3, sticky="ew", pady=(0, 8))
        
        # Champ DocStore ID
        ttk.Label(form, text="DocStore ID").grid(column=0, row=4, sticky="w", pady=(0, 4))
        docstore_entry = ttk.Entry(form, textvariable=self._docstore_id_var)
        docstore_entry.grid(column=0, row=5, sticky="ew", pady=(0, 8))
        
        # Frame pour les boutons
        button_frame = ttk.Frame(form)
        button_frame.grid(column=0, row=6, sticky="ew", pady=(16, 0))
        button_frame.columnconfigure(1, weight=1)
        
        # Bouton Retour
        back_btn = ttk.Button(
            button_frame,
            text="Retour",
            command=self._on_back
        )
        back_btn.grid(column=0, row=0, padx=(0, 8))
        
        # Bouton Charger CMX Documents
        submit_btn = ttk.Button(
            button_frame,
            text="Charger CMX Documents",
            command=self._on_submit
        )
        submit_btn.grid(column=2, row=0)
        
        # Configuration de la grille
        form.columnconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)
        
    def _on_submit(self) -> None:
        profile = self._profile_var.get().strip()
        enduser = self._enduser_var.get().strip()
        docstore_id = self._docstore_id_var.get().strip()
        
        if not profile:
            messagebox.showwarning("Champ requis", "Le CMX Profile est requis.")
            return
        if not enduser:
            messagebox.showwarning("Champ requis", "Le CMX Enduser est requis.")
            return
        if not docstore_id:
            messagebox.showwarning("Champ requis", "Le DocStore ID est requis.")
            return
            
        try:
            response = self._cmx_service.get_documents(
                jwt=self._current_jwt,
                profile=profile,
                enduser=enduser,
                store_id=docstore_id
            )
            # TODO: Traiter la réponse (par exemple l'afficher dans une nouvelle fenêtre)
            messagebox.showinfo(
                "Succès",
                f"Les documents ont été récupérés avec succès.\nNombre de documents : {len(response)}"
            )
        except requests.RequestException as e:
            messagebox.showerror(
                "Erreur",
                f"Erreur lors de la récupération des documents CMX : {str(e)}"
            )


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
        self._current_jwt = None  # Variable pour stocker le JWT courant

        self._client_id_var = tk.StringVar()
        self._client_secret_var = tk.StringVar()
        self._environment_var = tk.StringVar(value=self._environments[0].name)
        
        # Variable pour l'indicateur de statut du JWT
        self._jwt_status_var = tk.StringVar(value="Aucun JWT stocké")
        self._jwt_status_label = None
        
        # Frames de l'application
        self._auth_frame = None
        self._profile_frame = None
        
        self._build_widgets()

    def _build_widgets(self) -> None:
        """Construit tous les widgets de l'application."""
        # Container principal pour les formulaires
        self._container = ttk.Frame(self)
        self._container.grid(column=0, row=0, sticky="nsew")
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)
        
        # Création du formulaire d'authentification
        self._auth_frame = ttk.Frame(self._container)
        self._auth_frame.grid(column=0, row=0, sticky="nsew")
        self._container.columnconfigure(0, weight=1)
        self._container.rowconfigure(0, weight=1)

        # Construction du formulaire d'authentification
        self._build_auth_form()
        
    def _build_auth_form(self) -> None:
        """Construit le formulaire d'authentification."""
        # Labels et champs de saisie
        ttk.Label(self._auth_frame, text="Client ID").grid(column=0, row=0, sticky="w", pady=(0, 4))
        client_id_entry = ttk.Entry(self._auth_frame, textvariable=self._client_id_var)
        client_id_entry.grid(column=0, row=1, sticky="ew", pady=(0, 8))
        client_id_entry.focus()

        ttk.Label(self._auth_frame, text="Client Secret").grid(
            column=0, row=2, sticky="w", pady=(0, 4)
        )
        secret_entry = ttk.Entry(self._auth_frame, textvariable=self._client_secret_var, show="•")
        secret_entry.grid(column=0, row=3, sticky="ew", pady=(0, 8))

        ttk.Label(self._auth_frame, text="Environnement").grid(
            column=0, row=4, sticky="w", pady=(0, 4)
        )
        env_combo = ttk.Combobox(
            self._auth_frame,
            textvariable=self._environment_var,
            values=[env.name for env in self._environments],
            state="readonly",
        )
        env_combo.grid(column=0, row=5, sticky="ew", pady=(0, 8))
        env_combo.bind("<<ComboboxSelected>>", self._on_environment_change)

        submit_btn = ttk.Button(
            self._auth_frame,
            text="Obtenir un JWT",
            command=self._on_request_token,
        )
        submit_btn.grid(column=0, row=6, sticky="ew", pady=(8, 0))

        self._auth_frame.columnconfigure(0, weight=1)

        # Zone d'affichage du JWT
        result_label = ttk.Label(self._auth_frame, text="Jeton JWT :")
        result_label.grid(column=0, row=7, sticky="sw", pady=(16, 4))

        self._result_text = tk.Text(self._auth_frame, height=6, wrap="word")
        self._result_text.grid(column=0, row=8, sticky="nsew")
        self._result_text.configure(state="disabled")

        # Frame pour les boutons
        button_frame = ttk.Frame(self._auth_frame)
        button_frame.grid(column=0, row=9, sticky="ew", pady=(8, 0))
        button_frame.columnconfigure(1, weight=1)  # Pour espacer les boutons

        # Bouton pour supprimer le JWT
        clear_btn = ttk.Button(button_frame, text="Supprimer JWT", command=self._clear_jwt)
        clear_btn.grid(column=0, row=0, padx=(0, 8))

        # Bouton pour copier
        copy_btn = ttk.Button(button_frame, text="Copier", command=self._copy_to_clipboard)
        copy_btn.grid(column=2, row=0)

        # Indicateur de statut du JWT
        self._jwt_status_label = ttk.Label(
            self._auth_frame,
            textvariable=self._jwt_status_var,
            font=("TkDefaultFont", 9, "italic")
        )
        self._jwt_status_label.grid(column=0, row=10, sticky="w", pady=(8, 0))
        
        # Configuration de la grille
        self._auth_frame.rowconfigure(8, weight=1)  # Pour que la zone de texte s'étende

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

        # Stockage du JWT dans la session
        self._current_jwt = token
        self._display_token(token)
        self._update_jwt_status()
        
        # Navigation vers le formulaire de profil
        self._show_profile_frame()
        
    def get_current_jwt(self) -> str | None:
        """Retourne le JWT stocké dans la session courante.
        
        Returns
        -------
        str | None
            Le JWT courant ou None si aucun JWT n'a été généré
        """
        return self._current_jwt if is_jwt_valid(self._current_jwt) else None

    def _clear_jwt(self) -> None:
        """Supprime le JWT de la session."""
        if not self._current_jwt:
            messagebox.showinfo("Information", "Aucun JWT n'est actuellement stocké.")
            return
            
        self._current_jwt = None
        self._display_token("")
        self._update_jwt_status()
        messagebox.showinfo("Succès", "Le JWT a été supprimé de la session.")

    def _update_jwt_status(self) -> None:
        """Met à jour l'indicateur de statut du JWT."""
        if not self._current_jwt:
            self._jwt_status_var.set("Aucun JWT stocké")
            self._jwt_status_label.configure(foreground="gray")
        elif is_jwt_valid(self._current_jwt):
            self._jwt_status_var.set("JWT valide stocké")
            self._jwt_status_label.configure(foreground="green")
        else:
            self._jwt_status_var.set("JWT expiré")
            self._jwt_status_label.configure(foreground="red")

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


    def _show_auth_frame(self) -> None:
        """Affiche le formulaire d'authentification."""
        if self._profile_frame:
            self._profile_frame.grid_remove()
        self._auth_frame.grid(column=0, row=0, sticky="nsew")
        
    def _show_profile_frame(self) -> None:
        """Affiche le formulaire de profil."""
        if not self._profile_frame:
            # On utilise le service d'authentification pour obtenir l'environnement
            current_env = self._auth_service.environments[self._environment_var.get()]
            self._profile_frame = ProfileFrame(
                self._container,
                on_back=self._show_auth_frame,
                current_jwt=self._current_jwt,
                environment=current_env
            )
            
        self._auth_frame.grid_remove()
        self._profile_frame.grid(column=0, row=0, sticky="nsew")
        

def main() -> None:
    """Launch the authentication application."""

    app = AuthApp()
    app.mainloop()


if __name__ == "__main__":
    main()
