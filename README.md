# NetScanner Pro (scanner.py)

Documentation d'utilisation — NetScanner Pro v3.0

Résumé
-------
NetScanner Pro est un scanner réseau autonome écrit uniquement avec la stdlib Python (3.8+).
Il fournit : découverte d'hôtes, scan TCP (connect), SYN scan (root), inspection SSL/TLS,
analyse HTTP, recon DNS, traceroute, génération de rapport HTML/JSON et une TUI curses.

Points importants
-----------------
- Aucun paquet externe requis (tout est en stdlib).
- Pour lancer un `SYN scan` il faut les privilèges root (ou capabilities réseau appropriées).
- Le projet génère par défaut deux types de rapports si option `-o/--output` est fourni :
	JSON (données brutes) et HTML (rapport lisible).

Installation
------------
1. Cloner le dépôt :

```bash
git clone https://github.com/pentagone-numerique/scanner.py
cd scanner.py
```

2. Utiliser Python 3.8+ (un venv est recommandé) :

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Usage rapide
------------
Exemples :

```bash
# Scan d'une IP (top100 ports)
python3 scanners.py 192.168.1.1

# Découverte sur un /24 et génération de rapport
python3 scanners.py 192.168.1.0/24 --discover -o rapport

# Mode TUI
python3 scanners.py 192.168.1.0/24 --tui -o rapport

# SYN scan (nécessite root)
sudo python3 scanners.py 192.168.1.1 --syn -p 1-1024 -o rapport

# Mode rapide et sauvegarde partielle (utile pour gros réseaux)
python3 scanners.py 192.168.1.0/24 --fast --save-progress -o rapport
```

Options principales
-------------------
- `target` : IP, hôte ou réseau (ex. `192.168.1.0/24`, `example.com`).
- `-p/--ports` : `top100` (par défaut) | `top1000` | `all` | plage `1-1024` | liste `22,80,443`.
- `-T/--timeout` : timeout réseau (secondes).
- `-w/--workers` : nombre de threads pour les scans.
- `--syn` : utiliser le SYN scan (requiert root).
- `--trace` : effectuer un traceroute.
- `--discover` : effectuer seulement la découverte d'hôtes.
- `--no-ssl` / `--no-http` / `--no-dns` : désactiver certaines étapes.
- `-o/--output` : préfixe des fichiers de sortie (`préfixe.json` + `préfixe.html`).
- `--tui` : lancer l'interface curses interactive.
- `--save-progress` : sauvegarde JSON partielle pendant le scan (nécessite `-o`).
- `--save-interval` : intervalle (s) entre sauvegardes partielles (par défaut 3s).
- `--fast` : mode rapide (réduit timeout et augmente workers automatiquement).

Sortie et rapports
------------------
- `préfixe.json` : résultats bruts (JSON) pour post-traitement.
- `préfixe.html` : rapport HTML riche avec graphiques SVG et sections détaillées.
- Si `--save-progress` est activé, un fichier `préfixe.partial.json` est écrit périodiquement,
	permettant de récupérer l'état en cas d'interruption.

Conseils opérationnels
----------------------
- Exécutez en tant qu'utilisateur non-root pour les scans TCP classiques. Utilisez `--syn`
	uniquement quand vous contrôlez l'environnement et avez l'autorisation d'agir en root.
- Pour une exécution plus rapide sur grands réseaux, combinez `--fast` et `--save-progress`.
- Respectez la législation et les politiques locales avant de scanner des réseaux qui ne
	vous appartiennent pas. L'utilisation malveillante est interdite.

Debug & récupération
--------------------
- En cas d'interruption (`Ctrl-C`) avec `--save-progress`, les résultats déjà collectés
	seront sauvegardés et peuvent être réutilisés.
- Les logs succincts sont également disponibles dans l'interface TUI pendant l'exécution.

Contribution
------------
PRs bienvenues. Pour contributions :

1. Forkez le dépôt
2. Créez une branche feature/bugfix
3. Ouvrez une PR avec description claire

Licence
-------
Voir le fichier `LICENSE` dans le dépôt.

Fichiers clés
-------------
- `scanners.py` — script principal (contenu complet du scanner).
- `scanners.py` peut être copié sous `netscanner.py` si vous préférez ce nom.

Support
-------
Si vous souhaitez que je crée `netscanner.py` identique à `scanners.py`, dites-le et
je le ferai puis je commiterai/pusherai le changement.

