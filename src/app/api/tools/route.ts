/**
 * GET /api/tools — catalogue des moteurs d'audit (contrat worklog §F.19, §B, §I)
 * Le statut (CONNECTE | HORS_LIGNE) reflète le ping /internal/health du moteur :3030.
 */
import { NextResponse } from 'next/server'
import { requireAuth } from '@/lib/auth'
import { engineHealth } from '@/lib/engine-client'
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
      "Système multi-agents spécialisé dans l'audit approfondi : un agent de reconnaissance, un agent d'analyse " +
      "et un agent de vérification qui rejoue les preuves de concept en sandbox DiD avant de les confirmer.",
    nature: 'Multi-agents coordonnés (recon / analyse / vérification)',
    integration: 'RAG code, semgrep, analyse statique',
    sandbox: 'Sandbox DiD (isolation complète des PoC)',
    capabilities: ['Multi-agents (recon/analyse/vérification)', 'PoC en sandbox DiD', 'RAG code'],
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
  const tools = TOOL_CATALOG.map((tool) => ({
    ...tool,
    status: (online ? 'CONNECTE' : 'HORS_LIGNE') as ToolInfo['status'],
  }))
  return NextResponse.json({ tools })
})
