# Bioptim MVP local

Prototype applicatif complet pour Bioptim avec :

- creation de compte et connexion
- base SQLite reliee au front
- sessions et espace patient
- faux paiement de demonstration
- depot de fichiers (PDF / images)
- espace admin pour traiter les demandes

## Lancer le projet

Depuis le dossier du projet :

```powershell
python app.py
```

Puis ouvrir :

```text
http://127.0.0.1:8010
```

## Compte admin de demo

- email : `admin@bioptim.local`
- mot de passe : `DemoAdmin123!`

## Donnees stockees

- base locale : `bioptim.db`
- fichiers envoyes : dossier `uploads/`

## Remarques

- Le paiement est une simulation, aucun debit reel n'est effectue.
- Cette version est pensee pour une demo fonctionnelle et une etude de cas.
- Pour une mise en production avec de vraies donnees patients, il faudra renforcer fortement la conformite, la securite, l'hebergement et la gestion des donnees de sante.
