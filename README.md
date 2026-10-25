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
| **Sécurité de la plateforme** | RBAC 3 rôles, sessions signées HMAC-SHA256 (cookie httpOnly), **MFA** (code de démo statique sur les comptes de démo uniquement), rate limiting sur la connexion, en-têtes de sécurité HTTP (CSP…), journal d'audit immuable |
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

| Outil | Cibles supportées | Spécialité | Exécution réelle |
|---|---|---|---|
| **Phantom** | URL, Réseau | Agent IA offensif : reconnaissance, énumération, exploitation | ✅ adaptateur natif (agent ReAct authentique) |
| **DeepAudit** | Git | Audit de code multi-agents (Recon → Analyse → Vérification) | ✅ adaptateur API (plateforme distante) |
| **Basalt** | Git | Scanner ciblé avec **sentinelle `BASALT-POC-TRIGGERED`** | ✅ adaptateur natif (PoC exécuté réellement) |
| **RedAmon** | URL, Réseau | Reconnaissance et exploitation d'infrastructure (ports, sous-domaines, fingerprint) | ✅ adaptateur API (plateforme distante) |

> En mode `simulation` (ou lorsqu'un outil réel est indisponible), chaque outil est reproduit par un pipeline réaliste : phases pondérées, logs crédibles, constats structurés, sentinelles PoC — sans toucher aucune cible.

---

## ⚙️ Exécution réelle des outils — mode d'emploi

Le moteur d'exécution (`scan-engine`) fonctionne selon **deux modes**, contrôlés par la variable `TOOL_EXECUTION_MODE` :

| Mode | Comportement |
|---|---|
| `simulation` (défaut historique) | Pipelines simulés réalistes (phases, logs, constats) — **aucune cible touchée**. Idéal pour la démo et les tests. |
| `auto` (recommandé) | **Exécution réelle si l'outil est disponible** (binaire + Docker), sinon bascule en simulation avec une ligne de journal explicite dans le terminal du scan. |
| `real` | Exécution réelle stricte — le scan passe en échec si l'outil n'est pas prêt. |

### Outils réels intégrés (adaptateurs natifs)

| Outil | Adaptateur | Exécution |
|---|---|---|
| **Phantom** | ✅ natif — CLI `phantom scan -t <cible> -m quick\|standard\|deep --non-interactive --json` (agent ReAct authentique, sandbox Kali éphémère) | Requiert `pip install phantom-agent` + Docker + LLM |
| **Basalt** | ✅ natif — CLI `basalt audit <dépôt> --format json` (constats confirmés **uniquement si le PoC s'exécute** — sentinelle `BASALT-POC-TRIGGERED` réelle) | Requiert `pipx install basalt-scan` + Docker + LLM |
| **DeepAudit** | ✅ API — `POST /api/v1/projects` (dépôt Git cloné par la plateforme) → `agent-tasks` → polling progression → constats normalisés ; niveau de vérification selon profil (`analysis_only` / `sandbox` / `generate_poc`) | Requiert la plateforme DeepAudit déployée + `DEEPAUDIT_API_URL` / `DEEPAUDIT_EMAIL` / `DEEPAUDIT_PASSWORD` |
| **RedAmon** | ✅ API — `POST /api/projects` (cible URL→hôte ou IP/CIDR, modules selon profil) → `recon/{id}/start` → polling phases + journal SSE → graphe Neo4j (vulnérabilités nuclei/GVM/…) | Requiert la plateforme RedAmon déployée + `REDAMON_API_URL` / `REDAMON_EMAIL` / `REDAMON_PASSWORD` |

Le badge de chaque outil (vue **Outils**) indique le mode effectif et la raison d'une éventuelle indisponibilité (`GET /api/tools` → `realAvailable`, `realReason`).

### Configuration LLM (Z.ai)

Les outils réels sont des agents IA : ils ont besoin d'un LLM compatible OpenAI. AuditForge supporte **Z.ai** directement :

```bash
# Dans .env (ou variables du docker-compose)
TOOL_EXECUTION_MODE=auto
LLM_API_BASE=https://api.z.ai/api/paas/v4   # endpoint OpenAI-compatible Z.ai
LLM_API_KEY=votre-clé-zai
PHANTOM_LLM=openai/glm-4.6                  # format LiteLLM provider/model
BASALT_MODEL=glm-4.6
```

Un **pont LLM** (`mini-services/llm-bridge/`, port 3031) est également fourni : il expose un endpoint `/v1/chat/completions` standard adossé au SDK Z.ai — pratique pour le développement local ou pour centraliser la clé. En production, pointer directement vers `https://api.z.ai/api/paas/v4` est plus simple.

### Plateformes distantes : DeepAudit et RedAmon

Ces deux outils sont des **plateformes complètes** : ils se déploient eux-mêmes (leur propre `docker compose`, leurs propres bases de données) et le moteur AuditForge les pilote par API REST. Les adaptateurs sont **déjà intégrés** — il reste à déployer chaque plateforme à côté du moteur puis à déclarer sa connexion dans l'environnement du moteur :

```bash
# ── DeepAudit (audit de code multi-agents) ─────────────────────────
git clone https://github.com/lintsinghua/DeepAudit.git && cd DeepAudit
cp backend/.env.example backend/.env        # configurer Postgres + LLM
# LLM : LLM_PROVIDER=openai + LLM_API_KEY=… + LLM_BASE_URL=https://api.z.ai/api/paas/v4
docker compose -f docker-compose.prod.yml up -d     # backend :8000
# créer un compte (POST /api/v1/auth/register ou interface), puis côté AuditForge :
#   DEEPAUDIT_API_URL=http://<hôte-deepaudit>:8000
#   DEEPAUDIT_EMAIL=… / DEEPAUDIT_PASSWORD=…

# ── RedAmon (reconnaissance offensive en conteneurs) ───────────────
git clone https://github.com/samugit83/redamon.git && cd redamon
./redamon.sh install                        # ≥ 8 Go RAM recommandés ; webapp :3000
# créer un compte via l'interface, puis côté AuditForge :
#   REDAMON_API_URL=http://<hôte-redamon>:3000
#   REDAMON_EMAIL=… / REDAMON_PASSWORD=…
```

Notes :
- **DeepAudit** audite du **code** : seules les cibles **GIT** lui sont proposées (la plateforme clone le dépôt elle-même). Son LLM se configure dans son propre `.env` (endpoint OpenAI-compatible — Z.ai fonctionne).
- **RedAmon** accepte les cibles **URL** (l'hôte est dérivé) et **Réseau** (IP ou CIDR — plafonné `/24` IPv4, `/104` IPv6 par la plateforme). Son LLM (phases IA optionnelles) se configure dans son interface web.
- Chaque plateforme doit être **joignable depuis le conteneur/serveur du moteur** (même réseau Docker ou hôte accessible) — sans quoi le badge indique « inaccessible » et le mode `auto` bascule en simulation.

### Prérequis de l'exécution réelle

1. **Docker** accessible par le moteur (en Docker Compose : montage `/var/run/docker.sock` déjà prévu) ;
2. **Binaires installés** : `pip install phantom-agent` et `pipx install basalt-scan` (l'image `Dockerfile.engine` les installe automatiquement) ;
3. **Premier scan Phantom** : l'image sandbox Kali (~13 Go) est téléchargée une seule fois ;
4. **Cibles autorisées** : Phantom et RedAmon acceptent les cibles URL et réseau ; Basalt et DeepAudit auditent du code (cibles GIT — clonée par le moteur pour Basalt, par la plateforme pour DeepAudit) ;
5. Les constats réels alimentent exactement le même pipeline que la simulation : temps réel socket.io, vulnérabilités, qualification, rapports PDF, journal d'audit.

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

> ⚠️ **Comptes créés uniquement en mode DÉMONSTRATION** (développement local, ou
> `DEMO_SEED=1` explicite). En production, **aucun compte public n'est créé** :
> définissez `ADMIN_USERNAME` / `ADMIN_PASSWORD` dans le `.env` pour créer le
> premier administrateur au premier démarrage, puis créez les autres comptes
> depuis l'interface.

| Identifiant | Mot de passe | Rôle | Notes |
|---|---|---|---|
| `admin` | `Admin123!` | **ADMIN** | MFA activée — code de démo STATIQUE : `123456` |
| `auditeur` | `Audit123!` | **AUDITOR** | Création / lancement / annulation / qualification |
| `observateur` | `View123!` | **VIEWER** | Lecture seule |

> 🔐 Le « TOTP » des comptes de démo est un code fixe (`123456`) — suffisant
> pour la démonstration, à ne JAMAIS activer en production. Le compte d'amorçage
> (`ADMIN_USERNAME`/`ADMIN_PASSWORD`) est créé **sans** MFA.

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
- Le schéma de base est appliqué automatiquement au démarrage du conteneur `app`.
- **Aucun compte n'est créé par défaut en production** : renseignez `ADMIN_USERNAME` / `ADMIN_PASSWORD` (amorçage) ou `DEMO_SEED=1` (démo only, identifiants publics).

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
| `TOOL_EXECUTION_MODE` (engine) | `simulation` / `auto` / `real` — voir section *Exécution réelle* | `auto` |
| `LLM_API_BASE` (engine) | Endpoint OpenAI-compatible des outils réels (Z.ai direct ou pont) | `https://api.z.ai/api/paas/v4` |
| `LLM_API_KEY` (engine) | Clé API LLM (Z.ai) pour les outils réels | — |
| `PHANTOM_LLM` / `BASALT_MODEL` | Modèle par outil (format LiteLLM / nom de modèle) | `openai/glm-4.6` / `glm-4.6` |
| `DEEPAUDIT_API_URL` / `DEEPAUDIT_EMAIL` / `DEEPAUDIT_PASSWORD` (engine) | Connexion à la plateforme DeepAudit (ex. `http://deepaudit-backend:8000`) | — |
| `REDAMON_API_URL` / `REDAMON_EMAIL` / `REDAMON_PASSWORD` (engine) | Connexion à la plateforme RedAmon (webapp, ex. `http://redamon-webapp:3000`) | — |
| `DEMO_SEED` (app) | `1` = créer les comptes de démo (identifiants publics) | `0` en production |
| `ADMIN_USERNAME` / `ADMIN_PASSWORD` (app) | Premier compte ADMIN créé au premier démarrage (amorçage) | — |
| `MAX_CONCURRENT_SCANS` (engine) | Plafond global de scans simultanés (protection VPS) | `3` |
| `SITE_ORIGIN` (engine) | Origine autorisée pour les handshakes socket.io (CORS) | réflexif |

---

## 🔐 Sécurité implémentée

- **Authentification** : mots de passe hachés **scrypt** (salt aléatoire, comparaison à temps constant), sessions `v1.<payload>.<signature>` HMAC-SHA256, cookie `httpOnly` + `SameSite=Lax` (+ `Secure` automatique dès que le site est servi en HTTPS — détection `X-Forwarded-Proto`, override `COOKIE_SECURE`), expiration 8 h.
- **MFA** sur le compte de démo admin (code statique `123456` — démonstration uniquement ; les comptes d'amorçage production sont créés sans MFA).
- **En-têtes de sécurité HTTP** : CSP, `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy`, `Permissions-Policy`, HSTS (appliquée automatiquement en HTTPS) — posés sur toutes les routes par `next.config.ts`.
- **Validation stricte des cibles** : schéma par type (URL `http(s)://…`, GIT `https://|ssh://|git@…`, NETWORK alphanumérique) — empêche l'injection d'options/transport (`ext::`, `-upload-pack`…) dans les CLI du moteur, vérifiée côté app ET côté moteur (défense en profondeur).
- **Environnement minimal des outils réels** : les CLI d'audit (et leurs conteneurs) reçoivent une allowlist de variables — jamais `AUTH_SECRET`, `ENGINE_INTERNAL_TOKEN` ni les clés LLM inutiles.
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
├── Dockerfile.engine           # Image moteur + outils réels (Phantom, Basalt)
├── Dockerfile.bridge           # Image pont LLM optionnel (mini-services/llm-bridge)
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
└── mini-services/
    ├── scan-engine/            # Moteur d'exécution (Bun + socket.io + Prisma)
    │   └── src/
    │       ├── index.ts        # HTTP /internal/* + socket.io + recovery
    │       ├── engine.ts       # Orchestration (branchement réel ⇄ simulation)
    │       ├── real-exec/      # ADAPTATEURS RÉELS : phantom.ts, basalt.ts,
    │       │                   #   proc.ts (subprocess), git-target.ts, env.ts
    │       ├── templates.ts    # Pipelines de simulation par outil
    │       └── session.ts      # Vérification des sessions (handshake)
    └── llm-bridge/             # Pont LLM OpenAI-compatible (Z.ai, :3031)
```

---

## 🧰 Dépannage

| Symptôme | Cause probable / solution |
|---|---|
| « Moteur hors ligne » dans l'interface | `scan-engine` n'est pas lancé (`mini-services/scan-engine && bun run dev`) ou `ENGINE_URL` incorrect |
| Badge « Simulation (réel indisponible) » | Voir la raison affichée sous le badge : binaire absent (`pip install phantom-agent` / `pipx install basalt-scan`), Docker indisponible, plateforme distante non configurée (`DEEPAUDIT_API_URL` / `REDAMON_API_URL`) ou injoignable, identifiants refusés |
| Scan réel en échec « Exécution réelle indisponible » | Mode `real` strict — installez l'outil manquant ou repassez en `auto` |
| Scan réel en échec LLM | Vérifiez `LLM_API_BASE` / `LLM_API_KEY` (endpoint OpenAI-compatible joignable depuis le moteur) |
| `429 Trop de tentatives` | Rate limiting de connexion — attendez la fin de la fenêtre de 10 min |
| Connexion refusée / scans en échec au lancement | Vérifiez que `ENGINE_INTERNAL_TOKEN` est **identique** dans `.env` (app) et `mini-services/scan-engine/.env` |
| `Environment variable not found: DATABASE_URL` | Créez `.env` depuis `.env.example` (chemin absolu recommandé) puis `bun run db:push` |
| Pas de logs temps réel derrière un proxy | Assurez-vous que `/socket.io/*` est bien routé vers le moteur (voir `Caddyfile.docker`) et que le proxy supporte les WebSocket |
| Comptes de démo absents | Le seed s'exécute au premier appel API — vérifiez les droits en écriture sur le fichier SQLite |

---

## 📜 Usage et responsabilité

Ce projet est fourni à des fins d'audit de sécurité **sur des périmètres autorisés**. L'exploitation d'outils offensifs contre des systèmes sans autorisation explicite est illégale. Les auteurs et contributeurs ne sauraient être tenus responsables d'un usage inadapté.
