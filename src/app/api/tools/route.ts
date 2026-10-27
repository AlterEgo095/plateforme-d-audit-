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

/** Catalogue statique — descriptions alignées sur les pipelines du worklog §I. */
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
