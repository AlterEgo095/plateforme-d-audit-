# 🛡️ AuditForge — Plateforme d'audit de sécurité unifiée

**AuditForge** est une application web 100 % auto-hébergeable qui unifie l'exploitation de plusieurs outils d'audit et de test d'intrusion — **Phantom**, **DeepAudit**, **Basalt** et **RedAmon** — derrière une **interface unique** : gestion de campagnes, exécution des scans en temps réel, consolidation des vulnérabilités, rapports imprimables et traçabilité complète.

> ⚠️ **Avertissement** — AuditForge est un outillage d'audit de sécurité destiné à être utilisé **exclusivement sur des systèmes dont vous avez l'autorisation explicite de tester** (périmètre contractualisé). Aucune cible ne doit être scannée sans accord préalable du propriétaire.

---

## ✨ Fonctionnalités

| Domaine | Capacités |
|---|---|
| **Tableau de bord** | Statistiques temps réel (scans actifs, campagnes, vulnérabilités ouvertes, critiques confirmées), répartition par sévérité et par outil, scans récents |
| **Campagnes** | Création (cible URL / dépôt Git / réseau, profil Rapide / Standard / Approfondi), sélection des outils avec **validation de compatibilité outil ⇄ cible**, lancement immédiat ou différé, relance (ré-exécution), suppression |
| **Scans en temps réel** | Progression et phase en direct, **terminal de logs streaming** (socket.io), annulation en cours, durées et compteurs |
| **Vulnérabilités** | Consolidation multi-outils, sévérité / confiance / CVSS / CVE, preuves et PoC, statut de qualification (Ouvert → Confirmé / Faux positif / Corrigé), recherche et filtres |
| **Rapports** | Document d'audit formel généré par scan (synthèse exécutive, groupement par sévérité, remédiations), **export PDF via impression** |
| **Sécurité de la plateforme** | RBAC 3 rôles, sessions signées HMAC-SHA256 (cookie httpOnly), **MFA (TOTP)**, rate limiting sur la connexion, journal d'audit immuable |
| **Multi-outils** | 4 moteurs intégrés avec phases, logs et constats propres à chaque outil ; sentinelles de vérification (PoC exécuté en sandbox sans réseau) |

---

## 🧭 Architecture

```
                        ┌──────────────────────────────┐
                        │      Navigateur (SPA FR)     │
                        └──────┬───────────────┬───────┘
                     REST /api │               │ socket.io (WebSocket)
                               ▼               ▼
┌──────────────────────────────────┐   ┌──────────────────────────┐
│   Application Next.js (port 3000)│   │  Moteur d'exécution      │
│  • Frontend React 19 + shadcn/ui │   │  scan-engine (port 3030) │
│  • API REST  (19 endpoints)      │   │  • rooms scan:{id}       │
│  • RBAC + sessions + MFA         │──▶│  • pipelines de phases   │
│  • Journal d'audit               │   │  • logs + constats       │
└───────────────┬──────────────────┘   └───────────┬──────────────┘
                │  Prisma                          │ Prisma
                ▼                                  ▼
        ┌──────────────────────────────────────────────┐
        │   SQLite partagée (mode WAL)                 │
        │   Users · Campaigns · Scans · Findings ·     │
        │   ScanLogs · AuditTrail                      │
        └──────────────────────────────────────────────┘
```

En **déploiement Docker**, un reverse proxy **Caddy** est le seul point d'entrée exposé (80/443) : `/socket.io/*` est routé vers le moteur, tout le reste vers l'application. Les conteneurs `app` et `engine` ne publient **aucun port** sur l'hôte — le moteur est strictement confiné au réseau Docker interne.

### Les quatre moteurs intégrés

| Outil | Cibles supportées | Spécialité | Vérification PoC |
|---|---|---|---|
| **Phantom** | URL, Réseau | Agent IA offensif : reconnaissance, énumération, exploitation | Mixte (probable / confirmé) |
| **DeepAudit** | URL, Git | Audit de code multi-agents (Recon → Analyse → Vérification) | ~70 % confirmés (agent de vérification) |
| **Basalt** | URL, Git | Scanner ciblé avec **sentinelle `BASALT-POC-TRIGGERED`** | 100 % vérifiés en sandbox sans réseau |
| **RedAmon** | URL, Réseau | Reconnaissance et exploitation d'infrastructure (ports, sous-domaines, fingerprint) | Mixte (confirmé / probable) |

---

## 🧪 Le moteur d'exécution — précision importante

Le mini-service `scan-engine` livré ici est un **moteur de simulation réaliste** : il reproduit fidèlement le déroulé d'une exécution (phases pondérées par outil, commandes réalistes, densité de logs, constats structurés avec preuves et PoC, sentinelles de vérification, durées par profil). Il rend la plateforme **complètement démontrable et testable de bout en bout, sans aucune dépendance extérieure ni risque**.

L'interface interne du moteur (`POST /internal/run`, `/internal/cancel`, `/internal/health`, événements socket.io) est **stables et documentées** : pour brancher les outils réels, il suffit de remplacer les pipelines de simulation par l'orchestration Docker réelle des sandboxes (Phantom / DeepAudit / RedAmon) et des exécutions CLI (Basalt), en conservant les mêmes contrats d'événements et de persistance. **Toute la couche plateforme — campagnes, temps réel, consolidation, RBAC, rapports, traçabilité — est finalisée.**

---

## 🚀 Démarrage rapide (développement local)

Prérequis : [Bun](https://bun.sh) ≥ 1.1, Node.js ≥ 20 (Pour Next 16).

```bash
# 1. Dépendances
bun install
cd mini-services/scan-engine && bun install && cd ../..

# 2. Variables d'environnement
cp .env.example .env                                  # adaptez DATABASE_URL (chemin absolu conseillé)
cp mini-services/scan-engine/.env.example \
   mini-services/scan-engine/.env                     # mêmes AUTH_SECRET / ENGINE_INTERNAL_TOKEN que .env

# 3. Base de données (schéma + comptes/campagne de démonstration au premier accès)
mkdir -p db
bun run db:push

# 4. Moteur d'exécution (terminal 1)
cd mini-services/scan-engine && bun run dev

# 5. Application (terminal 2)
bun run dev
```

➡️ Ouvrez `http://localhost:3000`.

### Comptes de démonstration

| Identifiant | Mot de passe | Rôle | Notes |
|---|---|---|---|
| `admin` | `Admin123!` | **ADMIN** | MFA activée — code TOTP de démo : `123456` |
| `auditeur` | `Audit123!` | **AUDITOR** | Création / lancement / annulation / qualification |
| `observateur` | `View123!` | **VIEWER** | Lecture seule |

> 🔐 **En production** : supprimez ces comptes de démonstration (ou changez leurs identifiants/mots de passe), désactivez le TOTP de démo et définissez vos propres `AUTH_SECRET` / `ENGINE_INTERNAL_TOKEN`.

### Permissions par rôle

| Action | VIEWER | AUDITOR | ADMIN |
|---|:-:|:-:|:-:|
| Consultation (tableau de bord, scans, constats, rapports, journal) | ✅ | ✅ | ✅ |
| Créer / lancer / relancer une campagne, annuler un scan | ❌ | ✅ | ✅ |
| Qualifier un constat (Confirmé / Faux positif / Corrigé) | ❌ | ✅ | ✅ |
| Supprimer une campagne, lister les utilisateurs | ❌ | ❌ | ✅ |

---

## 🐳 Déploiement VPS avec Docker Compose

Prérequis : Docker ≥ 24 + plugin `compose`, un nom de domaine pointant vers le VPS (optionnel, pour HTTPS automatique).

```bash
# 1. Récupérer le code
git clone https://github.com/AlterEgo095/plateforme-d-audit-.git auditforge
cd auditforge

# 2. Configuration
cp .env.example .env
openssl rand -hex 32   # → AUTH_SECRET
openssl rand -hex 32   # → ENGINE_INTERNAL_TOKEN   (les deux lignes du .env)

# 3. Lancer la pile complète (app + moteur + reverse proxy Caddy)
docker compose up -d --build
```

- Interface : `http://<IP-du-VPS>` (HTTP par défaut) — avec `SITE_DOMAIN=audit.exemple.com` dans le `.env`, **HTTPS est obtenu automatiquement** (certificats Let's Encrypt gérés par Caddy).
- La base SQLite est persistée dans le volume Docker `auditforge-data` (mode WAL, partagée entre `app` et `engine`).
- Le schéma de base est appliqué automatiquement au démarrage du conteneur `app`, et les comptes de démonstration sont créés au premier accès.

### Variables d'environnement (docker-compose)

| Variable | Rôle | Défaut |
|---|---|---|
| `AUTH_SECRET` | Secret de signature des sessions (HMAC-SHA256) — **obligatoire** | — |
| `ENGINE_INTERNAL_TOKEN` | Token exigé par le moteur sur `/internal/*` — **obligatoire** | — |
| `SITE_DOMAIN` | Domaine public (active HTTPS automatique) | `:80` (HTTP) |
| `HTTP_PORT` / `HTTPS_PORT` | Ports exposés par Caddy | `80` / `443` |
| `DATABASE_URL` (app + engine) | Chemin SQLite dans le volume | `file:/data/auditforge.db` |
| `ENGINE_URL` (app) | URL interne du moteur | `http://engine:3030` |
| `BIND_HOST` (engine) | Interface d'écoute — `0.0.0.0` **uniquement dans le réseau Docker** | `127.0.0.1` |

---

## 🔐 Sécurité implémentée

- **Authentification** : mots de passe hachés **scrypt** (salt aléatoire, comparaison à temps constant), sessions `v1.<payload>.<signature>` HMAC-SHA256, cookie `httpOnly` + `SameSite=Lax` (+ `Secure` en production), expiration 8 h.
- **MFA (TOTP)** pour les comptes à privilèges (réponse `428 mfaRequired` puis vérification du code).
- **Rate limiting** de la connexion : 5 échecs / 10 min par IP + identifiant (fenêtre glissante), avec réinitialisation au succès.
- **RBAC** serveur sur **tous** les endpoints (VIEWER / AUDITOR / ADMIN) + validations d'entrée **Zod** systématiques.
- **Token interne** `x-internal-token` exigé par chaque route `/internal/*` du moteur (les API d'orchestration ne sont pas exposées publiquement).
- **Socket.io authentifié au handshake** : cookie de session **ou** token signé (`GET /api/auth/socket-token`), rooms plafonnées (20/socket).
- **Confinement réseau** (Docker) : seul Caddy est publié ; le moteur n'écoute que sur le réseau interne et jamais sur l'hôte ; en local, il n'écoute que sur `127.0.0.1`.
- **Journal d'audit** immuable : connexion/déconnexion, création/lancement de campagnes, annulations, changements de statut des constats, générations de rapports.
- **Robustesse** : wrapper d'erreurs uniforme (aucune fuite de stack), récupération au boot (scans orphelins → `FAILED`), arrêt gracieux (SIGTERM → scans finalisés `CANCELLED`), verrous applicatifs par campagne (anti course-critique), sanitization des cibles avant interpolation dans les logs.

---

## 📡 API REST

Authentification par cookie de session (`af_session`). Erreurs uniformes `{ "error": "…" }`.

| Méthode | Endpoint | Rôle min. | Description |
|---|---|---|---|
| `POST` | `/api/auth/login` | — | Connexion (`428` si MFA requise) |
| `POST` | `/api/auth/logout` | — | Déconnexion |
| `GET` | `/api/auth/me` | — | Session courante |
| `GET` | `/api/auth/socket-token` | — | Token signé pour le handshake socket.io |
| `GET` | `/api/users` | ADMIN | Liste des utilisateurs |
| `GET` | `/api/dashboard` | — | Statistiques + distributions + éléments récents |
| `GET` | `/api/campaigns` | — | Campagnes (scans et compteurs agrégés) |
| `POST` | `/api/campaigns` | AUDITOR | Créer (+ lancement immédiat optionnel) |
| `GET` | `/api/campaigns/{id}` | — | Détail d'une campagne |
| `DELETE` | `/api/campaigns/{id}` | ADMIN | Supprimer (refusée si scans actifs) |
| `POST` | `/api/campaigns/{id}/launch` | AUDITOR | Relancer des outils (nouvelle exécution) |
| `GET` | `/api/scans?campaignId=&status=` | — | Liste des scans (filtres) |
| `GET` | `/api/scans/{id}` | — | Détail + constats |
| `GET` | `/api/scans/{id}/logs?after=&limit=` | — | Logs paginés (incrémental) |
| `POST` | `/api/scans/{id}/cancel` | AUDITOR | Annuler un scan en cours |
| `GET` | `/api/findings?severity=&tool=&status=&scanId=&q=` | — | Recherche/filtres de constats |
| `PATCH` | `/api/findings/{id}` | AUDITOR | Qualifier un constat |
| `GET` | `/api/reports/{scanId}` | — | Rapport d'audit (scan terminé requis) |
| `GET` | `/api/audit-log?limit=` | — | Journal d'audit |
| `GET` | `/api/tools` | — | Catalogue des outils + statut du moteur |

### Événements temps réel (socket.io)

| Sens | Événement | Contenu |
|---|---|---|
| client → serveur | `scan:subscribe` / `scan:unsubscribe` | `{ scanId }` (room `scan:{id}`) |
| serveur → tous | `scan:update` | progression, phase, statut, compteurs |
| serveur → tous | `scan:done` | statut final + résumé |
| serveur → room | `scan:log` | ligne de terminal horodatée (niveaux INFO/CMD/WARN/ERROR/SUCCESS/TOOL/AGENT) |
| serveur → room | `scan:finding` | nouveau constat détecté |

---

## 🗂️ Structure du projet

```
.
├── docker-compose.yml          # Pile complète (app + engine + Caddy)
├── Dockerfile                  # Image application Next.js (standalone)
├── Dockerfile.engine           # Image moteur d'exécution
├── Caddyfile.docker            # Reverse proxy (HTTPS automatique)
├── prisma/schema.prisma        # Modèle de données (SQLite)
├── src/
│   ├── app/
│   │   ├── page.tsx            # SPA unique (connexion + 8 vues)
│   │   └── api/                # 19 endpoints REST (App Router)
│   ├── components/audit/       # Vue dashboard, campagnes, scans, constats, rapports…
│   ├── hooks/use-socket.ts     # Client socket.io authentifié (singleton)
│   └── lib/                    # auth (scrypt/HMAC/MFA), RBAC, DTO, seed,
│                               # engine-client, rate-limit, mutex, audit trail…
└── mini-services/scan-engine/  # Moteur d'exécution (Bun + socket.io + Prisma)
    ├── prisma/schema.prisma    # Schéma identique (base partagée)
    └── src/
        ├── index.ts            # HTTP /internal/* + socket.io + recovery
        ├── engine.ts           # Orchestration des exécutions (rooms, persistance)
        ├── templates.ts        # Pipelines de phases + logs réalistes par outil
        └── session.ts          # Vérification des sessions (handshake)
```

---

## 🧰 Dépannage

| Symptôme | Cause probable / solution |
|---|---|
| « Moteur hors ligne » dans l'interface | `scan-engine` n'est pas lancé (`mini-services/scan-engine && bun run dev`) ou `ENGINE_URL` incorrect |
| `429 Trop de tentatives` | Rate limiting de connexion — attendez la fin de la fenêtre de 10 min |
| Connexion refusée / scans en échec au lancement | Vérifiez que `ENGINE_INTERNAL_TOKEN` est **identique** dans `.env` (app) et `mini-services/scan-engine/.env` |
| `Environment variable not found: DATABASE_URL` | Créez `.env` depuis `.env.example` (chemin absolu recommandé) puis `bun run db:push` |
| Pas de logs temps réel derrière un proxy | Assurez-vous que `/socket.io/*` est bien routé vers le moteur (voir `Caddyfile.docker`) et que le proxy supporte les WebSocket |
| Comptes de démo absents | Le seed s'exécute au premier appel API — vérifiez les droits en écriture sur le fichier SQLite |

---

## 📜 Usage et responsabilité

Ce projet est fourni à des fins d'audit de sécurité **sur des périmètres autorisés**. L'exploitation d'outils offensifs contre des systèmes sans autorisation explicite est illégale. Les auteurs et contributeurs ne sauraient être tenus responsables d'un usage inadapté.
