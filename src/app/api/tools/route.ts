/**
 * GET /api/tools — catalogue des moteurs d'audit (contrat worklog §F.19, §B, §I)
 * Le statut (CONNECTE | HORS_LIGNE) reflète le ping /internal/health du moteur :3030.
 */
import { NextResponse } from 'next/server'
import { requireAuth } from '@/lib/auth'
import { engineHealth, engineToolsStatus } from '@/lib/engine-client'
import { TOOL_TARGET_COMPAT } from '@/lib/dto'
import { withApi } from '@/lib/route-handler'
import type { ToolInfo } from '@/lib/types'

export const dynamic = 'force-dynamic'

/** Catalogue statique — descriptions alignées sur les pipelines du worklog §I + P5 arsenal. */
const TOOL_CATALOG: Omit<ToolInfo, 'status'>[] = [
  {
    id: 'PHANTOM',
    name: 'Phantom',
    description:
      "Agent offensif autonome (ReAct) piloté par LLM : reconnaissance, énumération, exploitation et " +
      "post-exploitation en chaîne, avec plus de 30 outils à disposition et décisions justifiées étape par étape.",
    nature: 'Agent autonome multi-étapes',
    integration: 'nmap, nuclei, sqlmap, ffuf, hydra',
    sandbox: 'Sans sandbox — actions journalisées dans le flux de scan',
    capabilities: ['ReAct agent 30+ outils', 'nmap/nuclei/sqlmap', 'Post-exploitation'],
    supportedTargets: [...TOOL_TARGET_COMPAT.PHANTOM],
    family: 'AGENT',
  },
  {
    id: 'DEEPAUDIT',
    name: 'DeepAudit',
    description:
      "Agent d'audit profond piloté par IA : à partir d'une reconnaissance exhaustive (empreinte HTTP/TLS/WAF, " +
      "ports, crawl, JS, formulaires, paramètres cachés, fuzzing de répertoires), un LLM construit un plan d'attaque " +
      "priorisé, pilote les outils offensifs (nuclei, sqlmap, dalfox, commix, nikto + sondes maison : traversée, " +
      "redirection ouverte, SSRF, CORS, fichiers sensibles…), puis re-juge chaque candidat sur les preuves brutes " +
      "avant de produire un rapport exhaustif. Pipeline déterministe en 5 phases — aucune phase ignorée.",
    nature: "Agent IA multi-phases (recon → plan → exploitation → vérification → rapport)",
    integration: 'nuclei, sqlmap, dalfox, commix, nikto, ffuf, arjun, katana, nmap, testssl + sondes maison',
    sandbox: 'Sandbox Docker Kali dédiée (auditforge/phantom-sandbox-plus) — outillage isolé, preuves brutes conservées',
    capabilities: [
      'Recon exhaustive (ports/TLS/WAF/crawl/JS/params cachés)',
      "Plan d'attaque priorisé par LLM",
      'Exploitation ciblée (SQLi/XSS/RCE/traversal/SSRF/CORS/exposure)',
      'Vérification LLM des preuves (faux positifs écartés)',
      'Rapport exhaustif avec PoC reproductibles',
    ],
    supportedTargets: [...TOOL_TARGET_COMPAT.DEEPAUDIT],
    family: 'AGENT',
  },
  {
    id: 'BASALT',
    name: 'Basalt',
    description:
      "Vérificateur de vulnérabilités par exécution de PoC en conteneur sans réseau : chaque confirmation " +
      "repose sur un effet observé côté serveur, matérialisé par la sentinelle BASALT-POC-TRIGGERED.",
    nature: 'Exécution contrôlée de preuves de concept',
    integration: 'Docker (conteneur éphémère), règles basalt-rules',
    sandbox: 'Sandbox sans réseau (aucun paquet sortant)',
    capabilities: ['Exécution de PoC', 'Sentinelle BASALT-POC-TRIGGERED', 'Sandbox sans réseau'],
    supportedTargets: [...TOOL_TARGET_COMPAT.BASALT],
    family: 'AGENT',
  },
  {
    id: 'REDAMON',
    name: 'Redamon',
    description:
      "Module de reconnaissance externe : énumération de sous-domaines, scan de ports, empreintes de services " +
      "et exploitation assistée, avec corrélation des vulnérabilités GVM/OpenVAS.",
    nature: 'Reconnaissance & exploitation assistée',
    integration: 'GVM/OpenVAS, amass, masscan',
    sandbox: 'Sans sandbox — scans passifs par défaut',
    capabilities: ['Recon sous-domaines/ports', 'GVM/OpenVAS', 'Exploitation assistée'],
    supportedTargets: [...TOOL_TARGET_COMPAT.REDAMON],
    family: 'AGENT',
  },
  // ── P5 « Arsenal » — piliers evergreen ──
  {
    id: 'SUBFINDER',
    name: 'Subfinder',
    description:
      "Énumération passive de sous-domaines (projet ProjectDiscovery) : interroge plus de 100 sources OSINT " +
      "(CT logs, passive DNS, archives, moteurs) en quelques secondes, sans envoyer une seule requête à la cible. " +
      "L'outil idéal pour une cartographie discrète et massive de la surface DNS.",
    nature: 'Recon passive (ProjectDiscovery, Go)',
    integration: 'crt.sh, virustotal, shodan, passive DNS, archives + 100 sources',
    sandbox: 'Sans sandbox — énumération 100% passive, aucune requête vers la cible',
    capabilities: [
      'Énumération passive > 100 sources',
      'Filtrage anti-wildcard',
      'Mode récursif (profil DEEP)',
    ],
    supportedTargets: [...TOOL_TARGET_COMPAT.SUBFINDER],
    family: 'RECON',
  },
  {
    id: 'AMASS',
    name: 'Amass',
    description:
      "Cartographie profonde de la surface d'attaque (projet OWASP) : corrélation OSINT (214 sources), " +
      "reverse DNS, CT logs et graphe d'intelligence pour révéler ce que les scans actifs ne voient pas — " +
      "infrastructures oubliées, alias CDN, candidats à la prise de contrôle de sous-domaine.",
    nature: 'Recon profonde OSINT + corrélation (OWASP, Go)',
    integration: 'CT logs, passive/reverse DNS, ASN, archives — mode passif strict',
    sandbox: 'Sans sandbox — mode passif strict (aucune requête active vers la cible)',
    capabilities: [
      'Corrélation multi-sources (214 sources)',
      'Détection de takeovers (CNAME pendants)',
      'Graphe d\'intelligence + corrélation ASN',
    ],
    supportedTargets: [...TOOL_TARGET_COMPAT.AMASS],
    family: 'RECON',
  },
  {
    id: 'HTTPX',
    name: 'httpx',
    description:
      "Sondes HTTP à grande vitesse (ProjectDiscovery) : identifie instantanément les services web vivants " +
      "parmi des milliers d'hôtes — statuts, titres, serveurs, technologies, CDN. L'inventaire vivant qui " +
      "alimente directement Nuclei, ZAP et ffuf.",
    nature: 'Sondes HTTP massives (ProjectDiscovery, Go)',
    integration: 'status-code, title, tech-detect, web-server, CDN — sortie JSONL',
    sandbox: 'Sans sandbox — sondes HTTP standard, suivi de redirections',
    capabilities: [
      'Fingerprint vivant (status/titre/tech/CDN)',
      'Détection de services sans TLS',
      'Sortie JSONL normalisée',
    ],
    supportedTargets: [...TOOL_TARGET_COMPAT.HTTPX],
    family: 'RECON',
  },
  {
    id: 'NUCLEI',
    name: 'Nuclei',
    description:
      "Scanner de signatures basé sur 12 000+ templates YAML (ProjectDiscovery) : la couverture CVE la plus " +
      "réactive de l'écosystème — les templates critiques sont publiés quelques heures après la divulgation. " +
      "PoC curl reproductibles, détections OOB (interactsh), variantes de sévérité par profil.",
    nature: 'Scan de signatures massif (ProjectDiscovery, Go)',
    integration: '12 000+ templates (cves, exposures, misconfig, tech), interactsh, rate-limit',
    sandbox: 'Sans sandbox — requêtes HTTP signées par templates, débit plafonné (150 req/s)',
    capabilities: [
      'Couverture CVE massive et réactive',
      'PoC curl reproductibles',
      'Détections OOB (blind SSRF/RCE)',
      'Sévérité par profil (QUICK épargne INFO)',
    ],
    supportedTargets: [...TOOL_TARGET_COMPAT.NUCLEI],
    family: 'DAST',
  },
  {
    id: 'NIKTO',
    name: 'Nikto',
    description:
      "Coup d'œil historique sur la configuration serveur : 6 500 tests (fichiers d'installation, alias " +
      "exposés, méthodes HTTP dangereuses, pages par défaut). Ancien mais complémentaire de Nuclei — " +
      "il voit ce que les scanners applicatifs ignorent.",
    nature: 'Scanner de configuration serveur (Perl)',
    integration: 'OSVDB, tuning plugins, sortie JSON',
    sandbox: 'Sans sandbox — tests de configuration standard, timeout 10s par requête',
    capabilities: [
      '6 500 tests de configuration',
      'Fichiers d\'installation et alias exposés',
      'Méthodes HTTP dangereuses (TRACE/PUT)',
    ],
    supportedTargets: [...TOOL_TARGET_COMPAT.NIKTO],
    family: 'DAST',
  },
  {
    id: 'ZAP',
    name: 'OWASP ZAP',
    description:
      "Référence open source du DAST automatisé (automation framework) : spider classique+AJAX, scan passif " +
      "(en-têtes, cookies, divulgations) puis scan actif (8 000+ requêtes). Déployé massivement en DevSecOps, " +
      "il est intégré ici via zap-baseline (rapport JSON normalisé).",
    nature: 'DAST automatisé (OWASP, Java — automation framework)',
    integration: 'zap-baseline.py (-J report), 200+ scanners passifs/actifs',
    sandbox: 'Sans sandbox — daemon headless, rate limit respecté sur les formulaires',
    capabilities: [
      'Spider + scan passif + scan actif',
      'En-têtes, cookies, CSP (plugins 10010/10038…)',
      'Rapport JSON normalisé (risques 0-3)',
    ],
    supportedTargets: [...TOOL_TARGET_COMPAT.ZAP],
    family: 'DAST',
  },
  {
    id: 'SEMGREP',
    name: 'Semgrep',
    description:
      "Analyse sémantique du code source (SAST) à la vitesse de 20-100k LOC/s : 2 400+ règles du registre " +
      "en mode taint (source → propage → sink), détection des motifs vulnérables avec extrait de code, " +
      "CWE et correctif suggéré. L'outil idéal pour l'intégration précoce.",
    nature: 'SAST sémantique rapide (Semgrep, OSS)',
    integration: 'registre de règles (auto ou chemin local), mode taint, sortie JSON',
    sandbox: 'Sans sandbox — lecture seule du dépôt cloné',
    capabilities: [
      'Mode taint (source → sink)',
      'Extraits de code + CWE + correctifs',
      'Règles personnalisables (SEMGREP_CONFIG)',
    ],
    supportedTargets: [...TOOL_TARGET_COMPAT.SEMGREP],
    family: 'CODE',
  },
  {
    id: 'TRIVY',
    name: 'Trivy',
    description:
      "Référence open source du scan de dépendances (SCA) et de secrets : analyse les lockfiles du dépôt " +
      "contre la base CVE (241k+ entrées), détecte les secrets codés en dur et les mauvaises configurations " +
      "Docker. La supply chain n'a plus d'angle mort.",
    nature: 'SCA + secrets + misconfig (Aquasecurity, Go)',
    integration: 'base CVE à jour, scanners vuln,secret, sortie JSON',
    sandbox: 'Sans sandbox — lecture seule du dépôt cloné, timeout 20 min',
    capabilities: [
      'Vulnérabilités de dépendances (CVE/CVSS)',
      'Détection de secrets (masqués côté plateforme)',
      'Mauvaises configurations Docker/K8s',
    ],
    supportedTargets: [...TOOL_TARGET_COMPAT.TRIVY],
    family: 'CODE',
  },
  {
    id: 'GITLEAKS',
    name: 'Gitleaks',
    description:
      "Détection de secrets dans le dépôt ET son historique complet : clés privées, jetons API, mots de " +
      "passe committés (12 000 commits balayés en minutes). Exécution avec --redact : les valeurs de " +
      "secrets ne quittent JAMAIS le workdir du moteur — seuls l'emplacement et la règle sont persistés.",
    nature: 'Détection de secrets (gitleaks, Go)',
    integration: 'règles par défaut v8 + allowlist, historique git complet',
    sandbox: 'Sans sandbox — lecture seule du dépôt cloné, valeurs masquées (--redact)',
    capabilities: [
      'Historique git complet (toutes branches)',
      'Clés privées → CRITICAL, jetons → HIGH',
      'Valeurs jamais persistées (--redact)',
    ],
    supportedTargets: [...TOOL_TARGET_COMPAT.GITLEAKS],
    family: 'CODE',
  },
  {
    id: 'SQLMAP',
    name: 'sqlmap',
    description:
      "L'outil de référence de l'injection SQL : plus de 30 techniques d'injection (boolean/time-based, " +
      "UNION, error, stacked, out-of-band), fingerprint du DBMS, confirmation par payloads reproductibles. " +
      "Exécution non supervisée (--batch) par profil — l'extraction de données (--dump) reste hors périmètre.",
    nature: 'Exploitation SQLi (sqlmapproject, Python)',
    integration: 'level/risk par profil, --batch, --forms (DEEP), sortie stdout parsée',
    sandbox: 'Sans sandbox — requêtes HTTP ciblées, threads plafonnés à 4, pas de --dump',
    capabilities: [
      'Toutes techniques d\'injection supportées',
      'Fingerprint DBMS + payloads reproductibles',
      'Profil modulé (level/risk 1/1 → 5/3)',
    ],
    supportedTargets: [...TOOL_TARGET_COMPAT.SQLMAP],
    family: 'EXPLOIT',
  },
  {
    id: 'FFUF',
    name: 'ffuf',
    description:
      "Le fuzzer web le plus rapide : découverte de répertoires, fichiers et endpoints cachés par brute " +
      "force de wordlists (seclists), avec autofilter anti-bruit. Chaque chemin découvert est qualifié " +
      "(indice sensible → LOW, simple recon → INFO) avec PoC curl.",
    nature: 'Fuzzing web massif (ffuf, Go)',
    integration: 'seclists (FFUF_WORDLIST), autofilter, sortie JSON',
    sandbox: 'Sans sandbox — 30 threads plafonnés, timeout 8s par requête',
    capabilities: [
      'Fuzzing répertoires/fichiers/paramètres',
      'Autofilter anti-faux-positifs',
      'Qualification automatique des chemins sensibles',
    ],
    supportedTargets: [...TOOL_TARGET_COMPAT.FFUF],
    family: 'EXPLOIT',
  },
]

export const GET = withApi(async () => {
  const session = await requireAuth()
  if (session instanceof NextResponse) return session

  const online = await engineHealth()
  // Statut d'exécution réelle par outil (peut prendre quelques secondes : sondes
  // des binaires) — best effort : indisponible si le moteur ne répond pas.
  const realStatus = online ? await engineToolsStatus() : null
  const statusByTool = new Map(realStatus?.map((s) => [s.tool, s]) ?? [])

  const tools = TOOL_CATALOG.map((tool) => {
    const real = statusByTool.get(tool.id)
    return {
      ...tool,
      status: (online ? 'CONNECTE' : 'HORS_LIGNE') as ToolInfo['status'],
      execMode: real?.mode,
      realAvailable: real?.realAvailable,
      realReason: real?.reason,
    }
  })
  return NextResponse.json({ tools })
})
