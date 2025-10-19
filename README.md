# Client graphique JWT

Cette application Python fournit une interface graphique simple (Tkinter) pour
renseigner un `clientId`, un `clientSecret` et choisir un environnement cible
avant de générer un jeton JWT signé localement.

## Prérequis

- Python 3.10 ou supérieur (Tkinter est inclus avec les distributions
  standard de Python sous Windows, macOS et la plupart des distributions
  Linux).

## Installation

Aucune dépendance externe n'est nécessaire. Clonez le dépôt puis, dans le même
répertoire :

```bash
python -m app
```

L'application se lance dans une fenêtre native.

## Tests

Les tests unitaires peuvent être exécutés avec `pytest` :

```bash
python -m pytest
```

Ils vérifient la génération du jeton JWT simulé.
