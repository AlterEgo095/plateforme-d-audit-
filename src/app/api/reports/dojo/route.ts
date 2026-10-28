/**
 * /api/reports/dojo — P5 : export DefectDojo (hub central des résultats).
 *
 * GET  ?campaignId=… → document JSON au format « Generic Findings Import » de
 *      DefectDojo (Import Scan / reimport-scan) : un constat par vulnérabilité,
 *      sévérités capitalisées (Critical/High/Medium/Low/Info), mitigation et
 *      impact séparés, tags outil + catégorie, active/verified dérivés de la
 *      confiance. Réponse téléchargeable (Content-Disposition attachment).
 *
 * POST { campaignId, push: true } → (optionnel) pousse le même document vers
 *      une instance DefectDojo configurée : DOJO_API_URL + DOJO_API_TOKEN
 *      (+ DOJO_ENGAGEMENT_ID). 501 explicite si non configuré — la plateforme
 *      ne fait JAMAIS de push silencieux vers un tiers.
 *
 * Les deux chemins exigent une session AUDITOR+/ADMIN. L'export est un
 * lecteur de la base existante : aucun constat n'est transformé ni déduit.
 */
import { NextRequest, NextResponse } from 'next/server'
import { z } from 'zod'
import { db } from '@/lib/db'
import { requireAuth } from '@/lib/auth'
import { writeAudit } from '@/lib/audit'
import { sortFindings } from '@/lib/dto'
import { withApi } from '@/lib/route-handler'
import type { Confidence, Severity } from '@/lib/types'

export const dynamic = 'force-dynamic'

/** Sévérités DefectDojo (capitalisation anglaise attendue par l'importeur générique). */
const DOJO_SEVERITY: Record<Severity, string> = {
  CRITICAL: 'Critical',
  HIGH: 'High',
  MEDIUM: 'Medium',
  LOW: 'Low',
  INFO: 'Info',
}

interface DojoFinding {
  title: string
  severity: string
  description: string
  mitigation: string
  impact: string
  active: boolean
  verified: boolean
  date: string
  cve?: string
  cwe?: number
  cvssv3?: number
  line_number?: number
  file_path?: string
  url?: string
  references?: string
  unique_id_from_tool: string
  tags: string[]
}

/**
 * F1 (audit v2) : les constats AuditForge ne portent pas de colonne CWE —
 * l'identifiant est pourtant présent dans les preuves produites par les
 * outils (ZAP « CWE-79 », Semgrep « CWE : 89 », Nuclei classification…).
 * DefectDojo attend un champ top-level NUMÉRIQUE `cwe` — on l'extraie de la
 * description + preuves + PoC (première occurrence), sinon absent.
 */
function extractCwe(...parts: string[]): number | undefined {
  const m = /CWE[-\s:]*(\d{1,4})\b/i.exec(parts.filter(Boolean).join(' '))
  if (!m) return undefined
  const n = Number(m[1])
  return Number.isInteger(n) && n > 0 && n <= 9999 ? n : undefined
}

/**
 * F1 (audit v2) : DefectDojo affiche les références externes depuis le champ
 * top-level `references` — on rassemble les URLs utiles (preuves, PoC,
 * description, remédiation URL unique), dédupliquées, dans l'ordre de
 * lecture, plafonnées à 5 × 500 caractères (hygiène d'import).
 */
function extractReferences(...parts: string[]): string | undefined {
  const urls = new Set<string>()
  for (const part of parts) {
    if (!part) continue
    for (const m of part.matchAll(/https?:\/\/[^\s)`'"<>\]]+/gi)) {
      urls.add(m[0].slice(0, 500))
      if (urls.size >= 5) break
    }
    if (urls.size >= 5) break
  }
  return urls.size > 0 ? Array.from(urls).join('\n') : undefined
}

async function buildDojoDocument(campaignId: string) {
  const campaign = await db.campaign.findUnique({
    where: { id: campaignId },
    include: {
      createdBy: { select: { username: true } },
      scans: { orderBy: { createdAt: 'asc' }, select: { id: true, tool: true, target: true } },
    },
  })
  if (!campaign) return null

  const scanById = new Map(campaign.scans.map((s) => [s.id, s]))
  const findings = await db.finding.findMany({
    where: { scan: { campaignId } },
    orderBy: { createdAt: 'asc' },
  })

  const dojoFindings: DojoFinding[] = sortFindings(findings).map((f) => {
    const scan = scanById.get(f.scanId)
    const location = (f.location ?? '').trim()
    const isUrl = /^https?:\/\//i.test(location)
    const lineMatch = /^(.*?):(\d+)$/.exec(location)
    const mitigation = (f.remediation ?? '').trim()
    const cvss = typeof f.cvss === 'number' && f.cvss > 0 ? f.cvss : undefined
    const verified = f.confidence === ('CONFIRMED' satisfies Confidence)
    const cwe = extractCwe(f.evidence, f.description, f.poc)
    const references = extractReferences(f.evidence, f.poc, f.description)
    return {
      title: `[${f.tool}] ${f.title}`,
      severity: DOJO_SEVERITY[f.severity as Severity] ?? 'Info',
      description: [
        f.description,
        '',
        `**Catégorie :** ${f.category}`,
        `**Confiance :** ${f.confidence}`,
        scan ? `**Scan :** ${f.tool} — ${scan.target}` : '',
        f.evidence ? `\n**Preuves :**\n\n\`\`\`\n${f.evidence.slice(0, 4000)}\n\`\`\`` : '',
        f.poc ? `\n**PoC :**\n\n\`\`\`\n${f.poc.slice(0, 2000)}\n\`\`\`` : '',
      ]
        .filter(Boolean)
        .join('\n'),
      mitigation: mitigation || "À définir avec l'équipe produit (constat importé depuis AuditForge).",
      impact: cvss
        ? `Impact évalué à CVSS ${cvss} (${f.severity}).`
        : `Sévérité ${f.severity} (évaluation AuditForge).`,
      active: f.status !== 'FIXED' && f.status !== 'FALSE_POSITIVE',
      verified,
      date: f.createdAt.toISOString().slice(0, 10),
      ...(f.cve ? { cve: f.cve } : {}),
      ...(cwe !== undefined ? { cwe } : {}),
      ...(cvss ? { cvssv3: cvss } : {}),
      ...(isUrl ? { url: location.slice(0, 2048) } : {}),
      ...(lineMatch && !isUrl
        ? { file_path: lineMatch[1].slice(0, 1024), line_number: Number(lineMatch[2]) || 1 }
        : {}),
      ...(references !== undefined ? { references } : {}),
      unique_id_from_tool: f.id,
      tags: [f.tool.toLowerCase(), f.category.toLowerCase()].filter(Boolean),
    }
  })

  return {
    name: `${campaign.name} — AuditForge`,
    tags: ['auditforge', `profil-${campaign.profile.toLowerCase()}`, campaign.targetType.toLowerCase()],
    scan_date: new Date().toISOString().slice(0, 10),
    findings: dojoFindings,
    _meta: {
      campaign: {
        id: campaign.id,
        target: campaign.target,
        targetType: campaign.targetType,
        profile: campaign.profile,
        sequential: campaign.sequential,
        createdAt: campaign.createdAt.toISOString(),
        createdBy: campaign.createdBy?.username ?? null,
      },
      counts: { findings: dojoFindings.length },
      format: 'DefectDojo Generic Findings Import (scan_type: "Generic Findings Import")',
    },
  }
}

export const GET = withApi(async (req: NextRequest) => {
  const session = await requireAuth(['AUDITOR', 'ADMIN'])
  if (session instanceof NextResponse) return session

  const campaignId = req.nextUrl.searchParams.get('campaignId') ?? ''
  if (!campaignId) {
    return NextResponse.json({ error: 'Paramètre campaignId requis' }, { status: 400 })
  }

  const doc = await buildDojoDocument(campaignId)
  if (!doc) {
    return NextResponse.json({ error: 'Campagne introuvable' }, { status: 404 })
  }

  await writeAudit(session.username, 'REPORT_DOJO_EXPORT', doc.name, `${doc.findings.length} constat(s)`)

  const safeName = doc.name.replace(/[^\w.-]+/g, '_').slice(0, 80)
  return new NextResponse(JSON.stringify(doc, null, 2), {
    status: 200,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Content-Disposition': `attachment; filename="auditforge-dojo-${safeName}.json"`,
      'Cache-Control': 'no-store',
    },
  })
})

const pushSchema = z.object({
  campaignId: z.string().min(1).max(64),
  push: z.boolean(),
})

export const POST = withApi(async (req: NextRequest) => {
  const session = await requireAuth(['AUDITOR', 'ADMIN'])
  if (session instanceof NextResponse) return session

  const parsed = pushSchema.safeParse(await req.json().catch(() => null))
  if (!parsed.success || !parsed.data.push) {
    return NextResponse.json(
      { error: 'Corps invalide — { campaignId, push: true } attendu' },
      { status: 400 }
    )
  }

  const dojoUrl = (process.env.DOJO_API_URL ?? '').trim().replace(/\/+$/, '')
  const dojoToken = (process.env.DOJO_API_TOKEN ?? '').trim()
  const engagementId = (process.env.DOJO_ENGAGEMENT_ID ?? '').trim()
  if (!dojoUrl || !dojoToken || !engagementId) {
    return NextResponse.json(
      {
        error:
          "Push DefectDojo non configuré — définir DOJO_API_URL, DOJO_API_TOKEN et DOJO_ENGAGEMENT_ID (env du service Next.js), ou utiliser l'export GET et importer le fichier manuellement.",
      },
      { status: 501 }
    )
  }

  const doc = await buildDojoDocument(parsed.data.campaignId)
  if (!doc) {
    return NextResponse.json({ error: 'Campagne introuvable' }, { status: 404 })
  }

  // Import multipart (API v2 DefectDojo) : le document JSON part comme fichier.
  const form = new FormData()
  form.append('scan_type', 'Generic Findings Import')
  form.append('engagement', engagementId)
  form.append('verified', 'true')
  form.append('active', 'true')
  form.append('scan_date', doc.scan_date)
  form.append('minimum_severity', 'Info')
  form.append(
    'file',
    new Blob([JSON.stringify(doc)], { type: 'application/json' }),
    'auditforge-dojo.json'
  )

  let res: Response
  try {
    res = await fetch(`${dojoUrl}/api/v2/import-scan/`, {
      method: 'POST',
      headers: { Authorization: `Token ${dojoToken}` },
      body: form,
      cache: 'no-store',
      signal: AbortSignal.timeout(30_000),
    })
  } catch (err) {
    return NextResponse.json(
      { error: `DefectDojo injoignable : ${err instanceof Error ? err.message : 'erreur réseau'}` },
      { status: 502 }
    )
  }

  if (!res.ok) {
    const body = await res.text().catch(() => '')
    return NextResponse.json(
      { error: `DefectDojo a refusé l'import (HTTP ${res.status})`, detail: body.slice(0, 500) },
      { status: 502 }
    )
  }

  const result = (await res.json().catch(() => ({}))) as { test?: number }
  await writeAudit(
    session.username,
    'REPORT_DOJO_PUSH',
    doc.name,
    `Push vers ${dojoUrl} (test DefectDojo #${result.test ?? '?'}) — ${doc.findings.length} constat(s)`
  )
  return NextResponse.json({ ok: true, test: result.test ?? null, findings: doc.findings.length })
})
