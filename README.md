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
| **Multi-outils** | 4 plateformes/agents IA avec phases, logs et constats propres à chaque outil ; sentinelles de vérification (PoC exécuté en sandbox sans réseau) |
| **Arsenal evergreen (P5)** | **11 outils durables intégrés** — recon : Subfinder, Amass, httpx · DAST : Nuclei (12k templates), Nikto, OWASP ZAP · SAST/SCA : Semgrep, Trivy, Gitleaks (--redact) · exploitation : sqlmap, ffuf. **Presets « Stratégie Evergreen »** en un clic, **chaînes d'outils séquentielles** (recon → DAST → exploitation), **export/push DefectDojo**, plafonds anti-flood, secrets jamais persistés |
| **Endurance (P4)** | **File d'attente moteur** — une campagne à 4 outils démarre toujours même au-delà du plafond de scans simultanés (dispatch FIFO à chaque libération, annulable en file) ; scans en file **qui survivent aux redémarrages** ; métriques moteur enrichies (queue, uptime, mémoire) |

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


## ⚔️ L'arsenal evergreen (P5) — outils durables intégrés

Au-delà des 4 plateformes/agents IA, le moteur intègre les **11 piliers open source** de l'audit profond
et du pentest (sélection « evergreen » : maturité, écosystème, précision prouvée). Chaque outil dispose
d'un adaptateur réel (framework générique : découverte binaire, args par profil, parsing JSON/JSONL,
plafonds anti-flood) ET d'un pipeline de simulation complet.

| Pilier | Outils | Cibles | Points forts |
|---|---|---|---|
| 🧭 Reconnaissance | **Subfinder**, **Amass**, **httpx** | URL, Réseau | Énumération passive 100+ sources, corrélation OSINT (takeovers), sondes HTTP vivantes |
| ⚔️ DAST | **Nuclei**, **Nikto**, **OWASP ZAP** | URL (+ Réseau) | 12 000+ templates CVE réactifs, configuration serveur, automation framework CI |
| 🔬 SAST / SCA / secrets | **Semgrep**, **Trivy**, **Gitleaks** | Git | Mode taint 20-100k LOC/s, dépendances + secrets, historique git complet **--redact** |
| 💥 Exploitation | **sqlmap**, **ffuf** | URL | Toutes techniques d'injection (confirmées, sans `--dump`), fuzzing avec autofilter |
| 📊 Reporting | **Export/push DefectDojo** | — | Format *Generic Findings Import* : `GET /api/reports/dojo?campaignId=…` (téléchargement) ou push API (`DOJO_API_URL` + `DOJO_API_TOKEN` + `DOJO_ENGAGEMENT_ID`) |

**Orchestration — la puissance vient de l'enchaînement, pas d'un outil unique :**

- **Presets « Stratégie Evergreen »** (assistant de campagne, un clic) : *Recon externe* (Subfinder+Amass+httpx),
  *Audit web complet* (Nuclei+ZAP+sqlmap+ffuf+Nikto), *Audit de code* (Semgrep+Trivy+Gitleaks+Basalt),
  *Agents IA* (Phantom+DeepAudit+RedAmon+Basalt). Seuls les outils compatibles avec la cible sont retenus.
- **Chaînes d'outils séquentielles** : l'option « exécution séquentielle » d'une campagne fait s'enchaîner
  les scans l'un après l'autre (recon → DAST → exploitation) au lieu de courir en parallèle — le résultat
  de chaque maillon alimente la lecture du suivant. Compatible file d'attente (P4), annulation en chaîne
  et reprise au boot.
- Jusqu'à **8 outils par campagne** (full arsenal), validation stricte outil ⇄ cible inchangée.

**Garde-fous appliqués aux adaptateurs arsenal :** plafonds de constats par scan (200-500 + constat de
troncature), débits plafonnés (nuclei 150 req/s, ffuf 30 threads, sqlmap 4 threads), `gitleaks --redact`
(valeurs de secrets JAMAIS persistées), sqlmap sans extraction de données, env sanitisée (m7) et timeout
global `REAL_SCAN_TIMEOUT_MIN`.

**Installation des binaires** (sur le conteneur/serveur du MOTEUR) :

```bash
# Recon (Go)
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/owasp-amass/amass/v4/cmd/amass@latest
# DAST
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
apt install nikto sqlmap
# ZAP : image officielle zaproxy/zap-stable (zap-baseline.py dans le PATH)
# SAST/SCA
pipx install semgrep
# trivy : https://trivy.dev (apt/brew) — gitleaks : releases GitHub / brew
# Exploitation
go install github.com/ffuf/ffuf/v2@latest
apt install seclists   # wordlists ffuf (ou FFUF_WORDLIST=…)
```

Sans installation, chaque outil est **honnêtement signalé indisponible** (vue Outils, sonde par binaire,
cache 60 s) et le mode `auto` bascule en simulation. Surcharges par env : `SUBFINDER_BIN`, `NUCLEI_BIN`,
`ZAP_COMMAND`, `SEMGREP_CONFIG`, `FFUF_WORDLIST`, … (voir `.env.example`).

**Hors périmètre CLI (assumé) :** *Burp Suite Professional* (commercial, workflow manuel — ses exports
XML s'importent dans DefectDojo comme les nôtres) et *CodeQL* (requiert l'infrastructure GitHub Actions ;
Semgrep couvre le SAST local). La convergence des résultats passe par le **hub DefectDojo**.

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

1. **Docker** accessible par le moteur — en Docker Compose : **proxy Docker filtrant** (P0.3, audit v2) — le moteur ne monte plus `/var/run/docker.sock` en brut : il passe par le service `docker-proxy` qui n'expose que les endpoints nécessaires aux sandboxes (containers/images/networks/volumes + POST) et bloque build/exec/secrets/swarm ;
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
| `MAX_CONCURRENT_SCANS` (engine) | Plafond global de scans simultanés (protection VPS) — **P4 : au-delà, mise en file d'attente FIFO au lieu d'un rejet** | `3` |
| `MAX_QUEUED_SCANS` (engine) | Capacité de la file d'attente moteur (P4) — au-delà : rejet explicite ; les scans en file **survivent aux redémarrages** (reprise au boot) | `100` |
| `LOG_RETENTION_DAYS` (engine) | Rétention des journaux de scan en jours (P3 — purges au boot puis chaque 24 h ; 0 désactive ; constats et AuditTrail intacts) | `30` |
| `*_BIN` / `ZAP_COMMAND` / `SEMGREP_CONFIG` / `FFUF_WORDLIST` (engine) | Surcharges des binaires arsenal (Subfinder, Amass, httpx, Nuclei, Nikto, ZAP, Semgrep, Trivy, Gitleaks, sqlmap, ffuf) — détection PATH automatique | noms standards |
| `DOJO_API_URL` / `DOJO_API_TOKEN` / `DOJO_ENGAGEMENT_ID` (app) | Push DefectDojo optionnel (POST /api/reports/dojo) — l'export GET fonctionne sans configuration | — |
| `SITE_ORIGIN` (engine) | Origine autorisée pour les handshakes socket.io (CORS) | réflexif |
| `PHANTOM_IMAGE` (engine) | Image sandbox Kali de Phantom (vide = défaut amont) | — |
| `PHANTOM_COMPRESSOR_LLM` (engine) | Modèle LiteLLM du compresseur mémoire de Phantom | `PHANTOM_LLM` amont |
| `DOCKER_HOST` (engine) | Endpoint Docker des sandboxes — posé par le compose vers le proxy filtrant | `tcp://docker-proxy:2375` |
| `BACKUP_HOST_DIR` (backup) | Répertoire hôte des sauvegardes planifiées (sidecar `backup`) | `/opt/auditforge/backups` |
| `BACKUP_KEEP` / `BACKUP_INTERVAL_SECONDS` (backup) | Rotation (nombre) et période (s) des sauvegardes | `7` / `86400` |
| `APP_MEM_LIMIT` / `APP_CPUS` (app) | Plafonds mémoire / CPU du conteneur applicatif (P2) | `512m` / `1.0` |
| `ENGINE_MEM_LIMIT` / `ENGINE_CPUS` (engine) | Plafonds mémoire / CPU du moteur (P2 — les sandboxes sont hors plafond, côté démon hôte) | `2g` / `2.0` |
| `CADDY_MEM_LIMIT` / `CADDY_CPUS` (caddy) | Plafonds mémoire / CPU du reverse proxy (P2) | `256m` / `1.0` |
| `BACKUP_MEM_LIMIT` (backup) | Plafond mémoire du sidecar de sauvegarde (P2) | `128m` |

### Sauvegarde et restauration (P0-1 + P1)

- **Sauvegarde planifiée** : le service `backup` (compose prod) exécute `scripts/auditforge-backup.sh` au démarrage puis toutes les `BACKUP_INTERVAL_SECONDS` (24 h par défaut) : checkpoint WAL, copie froide, `integrity_check`, rotation `BACKUP_KEEP` (7). Les fichiers sont écrits dans le répertoire **hôte** `BACKUP_HOST_DIR` (défaut `/opt/auditforge/backups`) — ils survivent à `docker compose down -v`.
- **Sauvegarde manuelle (cron hôte)** : le script fonctionne aussi directement sur l'hôte (chemins par défaut) — `30 3 * * * /opt/auditforge/scripts/auditforge-backup.sh >> /opt/auditforge/backups/backup.log 2>&1`.
- **Restauration** : `sudo scripts/auditforge-restore.sh /opt/auditforge/backups/auditforge-<TS>.db --auto` — vérifie l'intégrité **avant** toute modification, arrête `app`/`engine`/`backup`, conserve l'état courant (`*.pre-restore-<TS>`, jamais détruit), installe la sauvegarde, re-vérifie l'intégrité, relance la pile. `--dry-run` affiche le plan sans rien toucher.
- **Testez la restauration** après le premier déploiement (sur une copie, avec `--dry-run` puis un vrai run) — une sauvegarde non testée n'est pas une sauvegarde.

### Surveillance des sauvegardes (P3)

Chaque tentative de sauvegarde (succès **ou** échec) écrit `last-backup.json` dans le répertoire des sauvegardes : horodatage, statut (`ok`/`error`), durée, fichier produit et message d'erreur éventuel.

- **Healthcheck du sidecar `backup`** (P3) : le conteneur passe `unhealthy` — visible dans `docker ps` — si le dernier essai est en erreur, date de plus de 2 périodes (`2 × BACKUP_INTERVAL_SECONDS`) ou n'a jamais eu lieu. Un `unhealthy` veut dire : **plus de sauvegarde fiable, agissez** (`docker logs auditforge-backup-1`, disque plein ? base déplacée ?).
- **Contrôle manuel** : `cat /opt/auditforge/backups/last-backup.json` puis `ls -lht /opt/auditforge/backups | head` — le fichier le plus récent doit dater de moins de 24 h (hors périodes personnalisées).
- **Alerte externe (recommandé)** : un cron hôte qui vérifie la fraîcheur du JSON et notifie (mail/ntfy/…) en cas de `status: error` ou d'âge > `2 × BACKUP_INTERVAL_SECONDS` — l'auto-hébergement n'a pas d'équipe d'astreinte, c'est ce filet qui la remplace.

### Maintenance et exploitation au quotidien (P3)

- **Santé de la pile** : `docker ps --format 'table {{.Names}}\t{{.Status}}'` — tous les services doivent être `Up (healthy)` (`app`, `engine`, `docker-proxy`, `caddy`, `backup`). Un `unhealthy` quelconque se diagnostique par `docker logs <conteneur> --tail 50`.
- **Rétention des journaux de scan** : les lignes de terminal (`ScanLog`) sont purgées au-delà de `LOG_RETENTION_DAYS` (30 j par défaut, balayage au démarrage du moteur puis chaque 24 h ; `0` désactive). Les **constats** et le **journal d'audit** ne sont jamais supprimés — la base cesse de croître sans borne tout en conservant l'intégralité de la matière métier.
- **Rotation des logs conteneurs** : `json-file` 10 Mo × 3 (P2) — rien à faire.
- **Hygiène des dépendances** : `bun audit` avant chaque mise à jour ; les dépendances « tool-time » restantes (chaînes eslint / prisma CLI, sans chemin d'exécution applicatif) sont documentées au worklog. Les mises à jour dans les plages semver : `bun update` (jamais `--latest` sans revue — les majeures, ex. recharts 3, sont volontairement non suivies).
- **Après chaque `docker compose up -d --build`** : vérifier `docker ps` (healthy partout), se connecter à l'interface, lancer une campagne de test PHANTOM/QUICK sur une cible de laboratoire, contrôler le terminal live et la présence de la sauvegarde du jour.

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
- **Confinement réseau** (Docker) : seul Caddy est publié ; le moteur n'écoute que sur le réseau interne et jamais sur l'hôte ; en local, il n'écoute que sur `127.0.0.1`. Le démon Docker de l'hôte n'est jamais exposé au moteur en brut : **proxy Docker filtrant** (`docker-proxy` — endpoints sandboxes uniquement, build/exec/secrets/swarm refusés, healthcheck P1 : le moteur ne démarre que si le proxy répond).
- **Segmentation réseau (P2)** : trois réseaux Docker dédiés — `edge` (seul à sortir sur Internet), `data` (app ⇄ moteur, `internal: true`) et `docker-ctrl` (moteur ⇄ proxy Docker, `internal: true`) ; le sidecar `backup` n'a **aucune interface réseau** (`network_mode: none`) — fin du réseau plat où tout service joignait tout.
- **Confinement des conteneurs (P2)** : `no-new-privileges:true` sur **tous** les services, `cap_drop: ALL` (caddy ne conserve que `NET_BIND_SERVICE` pour écouter 80/443), plafonds `mem_limit`/`cpus`/`pids_limit` paramétrables (un dérèglement ne peut plus affamer le VPS), rotation des logs conteneurs (`json-file` 10 Mo × 3 — `/var/lib/docker` cesse de croître sans borne).
- **Healthchecks de bout en bout** : app (`/api/auth/me`), proxy Docker (`/_ping`, P1) et **moteur** (`/internal/health` + token interne, P2) — Caddy ne publie 80/443 qu'une fois la chaîne complète saine (`depends_on: service_healthy`).
- **Sauvegarde/restauration** : sauvegardes froides planifiées (checkpoint WAL + `integrity_check` + rotation) hors du volume Docker, script de restauration gardé-fou (rollback automatique en cas d'échec d'intégrité).
- **Observabilité des sauvegardes (P3)** : `last-backup.json` tracé sur chaque tentative + healthcheck du sidecar (`unhealthy` si échec ou sauvegarde périmée) — une sauvegarde silencieusement morte est détectable dans `docker ps`.
- **Journal d'audit** immuable : connexion/déconnexion, création/lancement de campagnes, annulations, changements de statut des constats, générations de rapports.
- **Robustesse** : wrapper d'erreurs uniforme (aucune fuite de stack), récupération au boot (scans orphelins → `FAILED`), arrêt gracieux (SIGTERM → scans finalisés `CANCELLED`), verrous applicatifs par campagne (anti course-critique), sanitization des cibles avant interpolation dans les logs.
- **File d'attente moteur (P4)** : au-delà du plafond `MAX_CONCURRENT_SCANS`, les scans sont mis en file FIFO et démarrent dès qu'une ressource se libère (plus de scans en échec « trop de scans simultanés » en heure de pointe) ; chaque entrée est re-vérifiée en base avant dispatch (un scan annulé en file ne démarre jamais) ; les scans QUEUED **survivent aux redémarrages** du moteur (re-dispatch au boot — seuls les RUNNING interrompus passent FAILED) ; `/internal/health` expose queue/limites/uptime/mémoire.
- **Arsenal sous contrôle (P5)** : les 11 outils evergreen s'exécutent avec des garde-fous intégrés — plafonds de constats par scan (anti-flood de la base), débits plafonnés (nuclei 150 req/s, ffuf 30 threads, sqlmap 4 threads), secrets gitleaks **jamais persistés** (`--redact`), sqlmap **sans extraction de données** (pas de `--dump`), recon 100 % passive (Subfinder/Amass), env sanitisée héritée (m7) et timeout global ; disponibilité réelle sondée par binaire (cache 60 s) — jamais de faux « connecté ».
- **Hygiène logicielle (P3)** : `bun audit` sans critique dans les dépendances d'exécution, `overrides` npm pour écraser les transitives vulnérables (lodash), mises à jour semver-revues (next 16.4, react 19.3, prisma 6.19.3, zod 4.6) ; rétention `ScanLog` (`LOG_RETENTION_DAYS`) — la base ne croît plus sans borne.

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
