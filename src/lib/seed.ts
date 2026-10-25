/**
 * AuditForge — Seed idempotent (comptes de démonstration + campagne de démo)
 *
 * Exécuté au premier appel API (mémo sur globalThis + promesse en cours pour
 * éviter les exécutions concurrentes). Idempotent : chaque bloc re-vérifie les
 * compteurs avant d'insérer. Ne lève jamais vers l'appelant.
 *
 * Contrats : comptes §C, journal d'audit §E. C2 (audit 8-a) : le seed des
 * comptes de DÉMONSTRATION (identifiants publics du README) est conditionné —
 * jamais automatiquement en production ; amorçage via ADMIN_USERNAME/ADMIN_PASSWORD.
 */
import { db } from '@/lib/db'
import { hashPassword } from '@/lib/auth'

const g = globalThis as unknown as {
  __afSeedDone?: boolean
  __afSeedInFlight?: Promise<void>
}

/** Garantit que la base contient les comptes et la campagne de démonstration. */
export async function ensureSeed(): Promise<void> {
  if (g.__afSeedDone) return
  if (g.__afSeedInFlight) return g.__afSeedInFlight
  g.__afSeedInFlight = runSeed()
    .then(() => {
      g.__afSeedDone = true
    })
    .catch((error) => {
      // Ne jamais faire échouer l'appelant : on journalise et on retentera au prochain appel.
      console.error('[seed] échec du seed initial', error)
      g.__afSeedDone = false
    })
    .finally(() => {
      g.__afSeedInFlight = undefined
    })
  return g.__afSeedInFlight
}

/** PRAGMA SQLite recommandés pour la cohabitation Next.js ⇄ moteur (WAL). Best effort. */
async function applyPragmas(): Promise<void> {
  try {
    // journal_mode RENVOIE une ligne ("wal") → $queryRawUnsafe obligatoire
    // ($executeRawUnsafe échoue avec "Execute returned results" — cf. moteur).
    // Idem pour busy_timeout=5000 (tout PRAGMA d'affectation renvoie sa valeur).
    await db.$queryRawUnsafe('PRAGMA journal_mode=WAL;')
    await db.$queryRawUnsafe('PRAGMA busy_timeout=5000;')
  } catch (error) {
    console.error('[seed] PRAGMA ignorés', error)
  }
}

// ─── Données de démonstration ────────────────────────────────────────

interface LogSeed {
  level: string
  source: string
  message: string
}

/** Étale des lignes de log sur la durée du scan (dernière ligne ≈ finishedAt). */
function spreadLogs(startedAt: Date, durationMs: number, logs: LogSeed[]) {
  const n = logs.length
  return logs.map((l, i) => ({
    ...l,
    ts: new Date(startedAt.getTime() + Math.round((durationMs * i) / Math.max(1, n - 1))),
  }))
}

const DEMO_TARGET = 'https://boutique-demo.local'

const PHANTOM_FINDINGS = [
  {
    tool: 'PHANTOM',
    title: "Identifiants par défaut sur la console d'administration",
    severity: 'CRITICAL',
    confidence: 'CONFIRMED',
    category: 'auth',
    cve: null,
    cvss: 9.4,
    location: 'POST /admin/login (admin:admin)',
    description:
      "La console d'administration répond au couple d'identifiants par défaut admin:admin. " +
      "Un attaquant obtient un accès administrateur complet sans aucune élévation de privilèges préalable, " +
      "avec possibilité de créer des comptes, modifier les prix et lire les commandes clients.",
    evidence:
      "Requête POST /admin/login avec le corps email=admin&password=admin → HTTP 302, " +
      "cookie de session administrateur émis (PHPSESSID), tableau de bord /admin/dashboard accessible.",
    poc: "curl -i -s -k -X POST 'https://boutique-demo.local/admin/login' -d 'email=admin&password=admin' | grep -i 'location: /admin/dashboard'",
    remediation:
      "Forcer la rotation des identifiants au premier démarrage, imposer une politique de mots de passe forts " +
      "et activer une double authentification sur la console d'administration.",
  },
  {
    tool: 'PHANTOM',
    title: "Injection SQL dans le endpoint d'authentification",
    severity: 'CRITICAL',
    confidence: 'CONFIRMED',
    category: 'injection',
    cve: null,
    cvss: 9.8,
    location: 'POST /login — paramètre `email`',
    description:
      "Le paramètre email du formulaire de connexion est concaténé directement dans une requête SQL. " +
      "Une injection time-based blind SQLi permet d'exfiltrer la table users (identifiants, hachages, rôles) " +
      "puis de se connecter à n'importe quel compte.",
    evidence:
      "Charge utile `' OR 1=1; SELECT SLEEP(5)-- -` dans le champ email : le serveur répond en 5,4 s " +
      "contre 120 ms en baseline — signature d'une injection SQL time-based confirmée.",
    poc: "sqlmap -u 'https://boutique-demo.local/login' --data='email=test&password=x' --technique=T --dbms=mysql --dbs",
    remediation:
      "Migrer vers des requêtes préparées (ORM paramétré), valider strictement le format de l'adresse e-mail " +
      "en entrée et journaliser les tentatives d'injection avec alerting.",
  },
  {
    tool: 'PHANTOM',
    title: 'Répertoire .git exposé publiquement',
    severity: 'HIGH',
    confidence: 'PROBABLE',
    category: 'recon',
    cve: null,
    cvss: 7.5,
    location: 'GET /.git/HEAD',
    description:
      "Le répertoire .git du dépôt source est servi publiquement par le serveur web. " +
      "La récupération de l'arborescence permet de reconstituer l'intégralité du code source, " +
      "y compris d'éventuels secrets (clés API, mots de passe d'infrastructure).",
    evidence:
      "GET /.git/HEAD renvoie `ref: refs/heads/main`. La récupération récursive des objets (git-dumper) " +
      "a permis de cloner le dépôt ; 3 clés API candidate ont été localisées dans config/secrets.php.",
    poc: 'python3 git_dumper.py https://boutique-demo.local/.git/ ./dump && git -C ./dump log --oneline | head -5',
    remediation:
      "Bloquer l'accès aux répertoires .git/.svn/.env au niveau du serveur web " +
      "(nginx : location ~ /\\.git { deny all; }) et retirer le dépôt du dossier de déploiement.",
  },
  {
    tool: 'PHANTOM',
    title: 'Suites de chiffrement TLS obsolètes (TLS 1.0 activé)',
    severity: 'LOW',
    confidence: 'PROBABLE',
    category: 'crypto',
    cve: null,
    cvss: 3.7,
    location: '443/tcp (nginx 1.18)',
    description:
      "Le serveur accepte encore les protocoles TLS 1.0/1.1 et des suites de chiffrement CBC dépréciées. " +
      "Cette configuration expose les clients historiques à des attaques de type downgrade (POODLE, BEAST) " +
      "et dégrade la note de conformité (PCI-DSS).",
    evidence:
      "nmap --script ssl-enum-ciphers -p 443 : TLSv1.0 accepté (3 suites CBC), TLSv1.1 accepté, " +
      "pas de forward secrecy sur 2 suites.",
    poc: 'nmap --script ssl-enum-ciphers -p 443 boutique-demo.local',
    remediation:
      "Désactiver TLS 1.0/1.1, restreindre aux suites AEAD (TLS_AES_128_GCM_SHA256, ECDHE+AESGCM) " +
      "et activer HSTS avec max-age 31536000.",
  },
]

const BASALT_FINDINGS = [
  {
    tool: 'BASALT',
    title: 'Injection SQL confirmée par exécution de PoC',
    severity: 'CRITICAL',
    confidence: 'CONFIRMED',
    category: 'injection',
    cve: null,
    cvss: 9.8,
    location: 'POST /api/articles/search — paramètre `q`',
    description:
      "Le PoC exécuté en sandbox (sans réseau sortant) a confirmé l'injection SQL sur le paramètre q " +
      "de l'API de recherche : lecture de la version du SGBD et du nom de la base courante sans authentification.",
    evidence:
      'Sandbox BASALT : requête `\' UNION SELECT sqlite_version(), database()-- -` → HTTP 200 contenant `3.39.4 | boutique_demo`.\n' +
      'BASALT-POC-TRIGGERED\n' +
      'Le PoC a produit un effet mesurable côté serveur en 340 ms.',
    poc: "curl -s 'https://boutique-demo.local/api/articles/search?q=%27%20UNION%20SELECT%20sqlite_version()%2Cdatabase()--%20-'",
    remediation:
      'Requêtes préparées et validation par liste blanche des champs ; déployer un WAF en mode détection le temps du correctif.',
  },
  {
    tool: 'BASALT',
    title: 'Path traversal confirmé (lecture /etc/passwd en sandbox)',
    severity: 'HIGH',
    confidence: 'CONFIRMED',
    category: 'path-traversal',
    cve: null,
    cvss: 7.8,
    location: 'GET /download — paramètre `file`',
    description:
      "Le endpoint de téléchargement ne normalise pas le paramètre file. Le PoC sandboxisé a lu /etc/passwd " +
      "via une traversée de répertoire classique, confirmant la vulnérabilité sans trafic réseau sortant.",
    evidence:
      'GET /download?file=../../etc/passwd → HTTP 200, première ligne `root:x:0:0:root:/root:/bin/bash`.\n' +
      'BASALT-POC-TRIGGERED\n' +
      '3 fichiers sensibles lisibles depuis la racine web.',
    poc: "curl -s 'https://boutique-demo.local/download?file=../../../../etc/passwd' | head -3",
    remediation:
      "Résoudre le chemin final (realpath) et imposer qu'il descende d'un répertoire de stockage dédié ; " +
      'refuser les séquences `..` et les chemins absolus.',
  },
  {
    tool: 'BASALT',
    title: 'ReDoS confirmé — blocage event-loop 12 s',
    severity: 'MEDIUM',
    confidence: 'CONFIRMED',
    category: 'dos',
    cve: null,
    cvss: 5.9,
    location: "POST /api/newsletter — expression régulière d'e-mail",
    description:
      "La validation d'e-mail côté serveur utilise une expression régulière catastrophique. Le PoC sandboxisé " +
      "a provoqué un blocage de l'event-loop de 12 secondes avec une charge utile de 60 octets, " +
      "rendant le service indisponible pour tous les utilisateurs.",
    evidence:
      "Charge utile `a@` + 58 × 'a' : latence mesurée 12 040 ms (baseline 90 ms), CPU worker à 100 %.\n" +
      'BASALT-POC-TRIGGERED\n' +
      'Blocage reproduit 3 fois sur 3 essais.',
    poc: "node -e \"const re=/^([a-zA-Z0-9]+)*@example.org$/; console.time('redos'); re.test('a'.repeat(58)+'!@example.org'); console.timeEnd('redos')\"",
    remediation:
      "Remplacer la regex par une validation simple (présence d'un @, longueur bornée) ou une bibliothèque auditée " +
      '(validator.js) ; borner la longueur des entrées à 254 caractères.',
  },
]

const PHANTOM_LOGS: LogSeed[] = [
  { level: 'INFO', source: 'system', message: 'Initialisation du scan PHANTOM — profil STANDARD sur ' + DEMO_TARGET },
  { level: 'INFO', source: 'system', message: 'Cible résolue : 10.20.0.42 (boutique-demo.local), nginx 1.18 détecté' },
  { level: 'CMD', source: 'phantom', message: 'nmap -sV -T4 --top-ports 1000 boutique-demo.local' },
  { level: 'TOOL', source: 'nmap', message: '22/tcp open ssh OpenSSH 8.4p1 · 80/tcp open http nginx 1.18 · 443/tcp open ssl/http nginx 1.18' },
  { level: 'INFO', source: 'phantom', message: 'Empreinte applicative : PHP 8.1, application « Boutique Démo » (framework maison)' },
  { level: 'CMD', source: 'phantom', message: 'nuclei -u https://boutique-demo.local -severity low,medium,high,critical -silent' },
  { level: 'WARN', source: 'nuclei', message: '[exposed-git] /.git/HEAD accessible — ref: refs/heads/main' },
  { level: 'CMD', source: 'phantom', message: 'ffuf -u https://boutique-demo.local/FUZZ -w raft-small-words.txt -mc 200,301,403' },
  { level: 'INFO', source: 'phantom', message: "Console d'administration découverte : /admin (formulaire de connexion)" },
  { level: 'CMD', source: 'phantom', message: "hydra -l admin -P top-1000.txt boutique-demo.local http-post-form '/admin/login:email=^USER^&password=^PASS^:F=erreur'" },
  { level: 'SUCCESS', source: 'phantom', message: 'Accès administrateur obtenu — identifiants par défaut admin:admin acceptés' },
  { level: 'CMD', source: 'phantom', message: "sqlmap -u 'https://boutique-demo.local/login' --data='email=a&password=b' --batch --technique=T --level=3" },
  { level: 'WARN', source: 'sqlmap', message: "Paramètre 'email' vulnérable : SQLi time-based (SLEEP(5) confirmé, latence 5,4 s)" },
  { level: 'INFO', source: 'phantom', message: 'Post-exploitation : lecture de config/app.php, 2 clés API extraites' },
  { level: 'SUCCESS', source: 'system', message: 'Scan terminé en 62s — 4 vulnérabilités dont 2 critique(s)' },
]

const BASALT_LOGS: LogSeed[] = [
  { level: 'INFO', source: 'system', message: 'Initialisation du scan BASALT — profil STANDARD sur ' + DEMO_TARGET },
  { level: 'INFO', source: 'basalt', message: 'Chargement de 128 règles de vérification (bundle basalt-rules v2.4)' },
  { level: 'CMD', source: 'system', message: 'docker create --network none --rm --name basalt-run basalt-runner:2.4' },
  { level: 'SUCCESS', source: 'system', message: 'Sandbox prête — réseau sortant coupé (aucun paquet ne peut quitter le conteneur)' },
  { level: 'CMD', source: 'basalt', message: 'basalt build-poc --target https://boutique-demo.local --checks sqli,traversal,redos' },
  { level: 'INFO', source: 'basalt', message: 'Exécution du PoC SQLi sur POST /api/articles/search (paramètre q)' },
  { level: 'TOOL', source: 'basalt', message: 'BASALT-POC-TRIGGERED — effet serveur mesuré en 340 ms, PoC validé' },
  { level: 'INFO', source: 'basalt', message: 'Exécution du PoC path traversal sur GET /download?file=../../etc/passwd' },
  { level: 'TOOL', source: 'basalt', message: 'BASALT-POC-TRIGGERED — /etc/passwd lu depuis la sandbox, PoC validé' },
  { level: 'WARN', source: 'basalt', message: 'ReDoS : latence 12 040 ms mesurée sur POST /api/newsletter (3 reproductions sur 3)' },
  { level: 'TOOL', source: 'basalt', message: 'Empreinte SGBD : SQLite 3.39.4, base « boutique_demo »' },
  { level: 'INFO', source: 'basalt', message: 'Rédaction du rapport : 3 confirmations, 0 faux positif, 0 non vérifié' },
  { level: 'SUCCESS', source: 'system', message: 'Scan terminé en 54s — 3 vulnérabilités dont 1 critique(s)' },
]

// ─── Corps du seed ───────────────────────────────────────────────────

/**
 * C2 (audit 8-a) : les comptes de démonstration ont des identifiants PUBLICS
 * (README GitHub). Sur un VPS fraîchement déployé, ils équivaut à un accès
 * admin mondial. Politique :
 * - DEMO_SEED=1    → seed de démo forcé (démo/dev explicite)
 * - DEMO_SEED=0    → seed interdit (production durcie)
 * - défaut         → seed uniquement hors production
 */
function demoSeedEnabled(): boolean {
  const v = process.env.DEMO_SEED
  if (v === '1') return true
  if (v === '0') return false
  return process.env.NODE_ENV !== 'production'
}

/**
 * Amorçage production : crée un premier compte ADMIN depuis les variables
 * d'environnement ADMIN_USERNAME/ADMIN_PASSWORD (sans MFA — à activer ensuite).
 * Retourne true si le compte a été créé.
 */
async function bootstrapAdmin(): Promise<boolean> {
  const username = process.env.ADMIN_USERNAME?.trim()
  const password = process.env.ADMIN_PASSWORD
  if (!username || !password) return false
  await db.user.create({
    data: {
      username,
      passwordHash: hashPassword(password),
      role: 'ADMIN',
      mfaEnabled: false,
    },
  })
  await db.auditTrail.create({
    data: {
      actor: 'système',
      action: 'SEED',
      resource: 'users',
      detail: `Compte administrateur initial créé (${username}) via ADMIN_USERNAME/ADMIN_PASSWORD`,
    },
  })
  console.log(`[seed] compte administrateur initial créé : ${username}`)
  return true
}

async function runSeed(): Promise<void> {
  await applyPragmas()
  const now = Date.now()

  // 1) Comptes : démonstration (mode démo uniquement) OU administrateur d'amorçage
  if ((await db.user.count()) === 0) {
    if (demoSeedEnabled()) {
      await db.user.createMany({
        data: [
          { username: 'admin', passwordHash: hashPassword('Admin123!'), role: 'ADMIN', mfaEnabled: true },
          { username: 'auditeur', passwordHash: hashPassword('Audit123!'), role: 'AUDITOR', mfaEnabled: false },
          { username: 'observateur', passwordHash: hashPassword('View123!'), role: 'VIEWER', mfaEnabled: false },
        ],
      })
      await db.auditTrail.create({
        data: {
          actor: 'système',
          action: 'SEED',
          resource: 'users',
          detail: 'Comptes de démonstration créés (admin, auditeur, observateur)',
        },
      })
    } else {
      const created = await bootstrapAdmin()
      if (!created) {
        console.warn(
          '[seed] aucun compte créé : définissez ADMIN_USERNAME/ADMIN_PASSWORD (amorçage production) ' +
            'ou DEMO_SEED=1 (comptes de démonstration, identifiants publics)',
        )
      }
    }
  }

  // 2) Campagne de démonstration (propriété d'admin) — mode démo uniquement
  if (demoSeedEnabled() && (await db.campaign.count()) === 0) {
    const admin = await db.user.findUnique({ where: { username: 'admin' } })
    if (admin) {
      const campaignCreatedAt = new Date(now - 3 * 3_600_000)
      const campaign = await db.campaign.create({
        data: {
          name: 'Audit initial — application vitrine',
          description: 'Campagne de démonstration générée au premier démarrage.',
          target: DEMO_TARGET,
          targetType: 'URL',
          profile: 'STANDARD',
          status: 'COMPLETED',
          createdById: admin.id,
          createdAt: campaignCreatedAt,
        },
      })

      // ── Scan PHANTOM (terminé il y a ~2 h 40) ──
      const phantomStart = new Date(now - (2 * 3_600 + 40 * 60) * 1000)
      const phantomEnd = new Date(now - (2 * 3_600 + 39 * 60) * 1000)
      const phantom = await db.scan.create({
        data: {
          campaignId: campaign.id,
          tool: 'PHANTOM',
          target: DEMO_TARGET,
          status: 'COMPLETED',
          progress: 100,
          phase: 'TERMINÉ',
          startedAt: phantomStart,
          finishedAt: phantomEnd,
          durationMs: 62000,
          findingsCount: 4,
          criticalCount: 2,
          createdAt: new Date(now - (2 * 3_600 + 41 * 60) * 1000),
        },
      })
      // Constats PHANTOM : dates de création étalées en fin de scan
      await db.finding.createMany({
        data: PHANTOM_FINDINGS.map((f, i) => ({
          ...f,
          scanId: phantom.id,
          sentinelTriggered: false,
          status: 'OPEN',
          createdAt: new Date(phantomEnd.getTime() - (PHANTOM_FINDINGS.length - 1 - i) * 8_000),
        })),
      })
      await db.scanLog.createMany({
        data: spreadLogs(phantomStart, 62000, PHANTOM_LOGS).map((l) => ({ ...l, scanId: phantom.id })),
      })

      // ── Scan BASALT (terminé il y a ~2 h 35) ──
      const basaltStart = new Date(now - (2 * 3_600 + 35 * 60) * 1000)
      const basaltEnd = new Date(now - (2 * 3_600 + 34 * 60) * 1000)
      const basalt = await db.scan.create({
        data: {
          campaignId: campaign.id,
          tool: 'BASALT',
          target: DEMO_TARGET,
          status: 'COMPLETED',
          progress: 100,
          phase: 'TERMINÉ',
          startedAt: basaltStart,
          finishedAt: basaltEnd,
          durationMs: 54000,
          findingsCount: 3,
          criticalCount: 1,
          createdAt: new Date(now - (2 * 3_600 + 36 * 60) * 1000),
        },
      })
      // Constats BASALT : sentinelles déclenchées, statut OPEN sauf le dernier (CONFIRMED)
      await db.finding.createMany({
        data: BASALT_FINDINGS.map((f, i) => ({
          ...f,
          scanId: basalt.id,
          sentinelTriggered: true,
          status: i === BASALT_FINDINGS.length - 1 ? 'CONFIRMED' : 'OPEN',
          createdAt: new Date(basaltEnd.getTime() - (BASALT_FINDINGS.length - 1 - i) * 8_000),
        })),
      })
      await db.scanLog.createMany({
        data: spreadLogs(basaltStart, 54000, BASALT_LOGS).map((l) => ({ ...l, scanId: basalt.id })),
      })

      // ── Entrées d'audit de la campagne de démo ──
      await db.auditTrail.createMany({
        data: [
          {
            actor: 'admin',
            action: 'CAMPAIGN_CREATE',
            resource: campaign.name,
            detail: 'Cible https://boutique-demo.local (STANDARD, URL)',
            createdAt: campaignCreatedAt,
          },
          {
            actor: 'admin',
            action: 'CAMPAIGN_LAUNCH',
            resource: campaign.name,
            detail: 'PHANTOM, BASALT',
            createdAt: new Date(now - (2 * 3_600 + 41 * 60) * 1000),
          },
        ],
      })
    }
  }
}
