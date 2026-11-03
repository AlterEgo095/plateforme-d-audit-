/**
 * /api/reports/sarif — Sprint 2 : export SARIF 2.1.0 (OASIS) des constats.
 *
 * GET ?campaignId=… | ?scanId=… → document SARIF 2.1.0 téléchargeable
 * (Content-Type application/sarif+json) compatible GitHub Code Scanning :
 * - runs[].tool.driver.rules : une règle par couple (outil, catégorie) —
 *   id « AF-<TOOL>-<catégorie> », helpUri vers la doc de la plateforme ;
 * - results[] : level mappé (CRITICAL/HIGH→error, MEDIUM→warning,
 *   LOW/INFO→note), message = titre + description, physicalLocation (URL de
 *   la localisation si présente, sinon la cible — uri encodée), region
 *   startLine 1, partialFingerprints = id du constat, properties (sévérité,
 *   confiance, CVSS, CVE, statut, sentinel).
 * Les constats FALSE_POSITIVE/FIXED sont exclus par défaut (paramètre
 * `includeResolved=true` pour les réintégrer) — le document reflète le
 * périmètre VULNÉRABLE remis au client / à l'outil d'agrégation.
 * Audit : REPORT_SARIF_EXPORT.
 */
import { NextRequest, NextResponse } from 'next/server'
import { db } from '@/lib/db'
import { requireAuth } from '@/lib/auth'
import { writeAudit } from '@/lib/audit'
import { sortFindings } from '@/lib/dto'
import { withApi } from '@/lib/route-handler'
import type { Severity } from '@/lib/types'

export const dynamic = 'force-dynamic'

/** Mapping sévérité AuditForge → level SARIF (error | warning | note | none). */
const SARIF_LEVEL: Record<Severity, 'error' | 'warning' | 'note' | 'none'> = {
  CRITICAL: 'error',
  HIGH: 'error',
  MEDIUM: 'warning',
  LOW: 'note',
  INFO: 'note',
}

/** ruleId stable par couple (outil, catégorie) — ex. AF-NUCLEI-XSS. */
function ruleId(tool: string, category: string): string {
  const cat = (category || 'general').toUpperCase().replace(/[^A-Z0-9]+/g, '-')
  return `AF-${tool.toUpperCase()}-${cat}`
}

/** URI d'artefact : localisation URL si présente, sinon la cible encodée. */
function artifactUri(location: string | null, target: string): string {
  const loc = (location ?? '').trim()
  if (/^https?:\/\//i.test(loc)) return loc.slice(0, 2048)
  if (/^https?:\/\//i.test(target)) return target.slice(0, 2048)
  return `target://${encodeURIComponent(target.slice(0, 200))}`
}

interface SarifFinding {
  id: string
  tool: string
  title: string
  severity: string
  confidence: string
  category: string
  cve: string | null
  cvss: number | null
  location: string | null
  description: string
  poc: string
  sentinelTriggered: boolean
  status: string
  remediation: string | null
  createdAt: Date
}

export async function buildSarifDocument(
  scope: { campaignId?: string; scanId?: string },
  includeResolved: boolean
) {
  // Résolution du périmètre : campagne (tous scans) ou scan unique.
  let campaignName = ''
  let campaignTarget = ''
  let scanTool: string | null = null
  let findings: SarifFinding[] = []

  if (scope.scanId) {
    const scan = await db.scan.findUnique({
      where: { id: scope.scanId },
      include: { campaign: { select: { name: true, target: true } } },
    })
    if (!scan) return null
    campaignName = scan.campaign.name
    campaignTarget = scan.target
    scanTool = scan.tool
    findings = await db.finding.findMany({
      where: { scanId: scope.scanId },
      take: 5000,
      orderBy: { createdAt: 'desc' },
    })
  } else if (scope.campaignId) {
    const campaign = await db.campaign.findUnique({
      where: { id: scope.campaignId },
      select: { name: true, target: true },
    })
    if (!campaign) return null
    campaignName = campaign.name
    campaignTarget = campaign.target
    findings = await db.finding.findMany({
      where: { scan: { campaignId: scope.campaignId } },
      take: 5000,
      orderBy: { createdAt: 'desc' },
    })
  } else {
    return null
  }

  const statusFilter = includeResolved
    ? undefined
    : { notIn: ['FALSE_POSITIVE', 'FIXED'] }
  const effective = sortFindings(
    statusFilter ? findings.filter((f) => !statusFilter.notIn.includes(f.status)) : findings
  )

  // Règles dédupliquées (ordre d'apparition) — description FR standardisée.
  const rules: {
    id: string
    name: string
    shortDescription: { text: string }
    fullDescription: { text: string }
    helpUri: string
    properties: Record<string, string>
  }[] = []
  const ruleIndex = new Map<string, number>()
  for (const f of effective) {
    const id = ruleId(f.tool, f.category)
    if (!ruleIndex.has(id)) {
      ruleIndex.set(id, rules.length)
      rules.push({
        id,
        name: `${f.tool}/${f.category}`,
        shortDescription: { text: `${f.tool} — catégorie ${f.category}` },
        fullDescription: {
          text:
            `Constats de catégorie « ${f.category} » produits par l'outil ${f.tool} ` +
            `lors des campagnes AuditForge (cible ${campaignTarget}).`,
        },
        helpUri: 'https://auditforge.aenews.online',
        properties: { 'auditforge/tool': f.tool, 'auditforge/category': f.category },
      })
    }
  }

  const results = effective.map((f) => {
    const id = ruleId(f.tool, f.category)
    return {
      ruleId: id,
      ruleIndex: ruleIndex.get(id) ?? 0,
      level: SARIF_LEVEL[f.severity as Severity] ?? 'note',
      message: {
        text:
          `${f.title}. ${f.description}`.trim().slice(0, 2000) +
          (f.remediation ? ` Remédiation : ${f.remediation}` : ''),
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: artifactUri(f.location, campaignTarget) },
            region: { startLine: 1, startColumn: 1 },
          },
        },
      ],
      partialFingerprints: { 'auditforge/findingId/v1': f.id },
      properties: {
        'auditforge/findingId': f.id,
        'auditforge/severity': f.severity,
        'auditforge/confidence': f.confidence,
        'auditforge/status': f.status,
        'auditforge/tool': f.tool,
        'auditforge/category': f.category,
        'auditforge/sentinelTriggered': f.sentinelTriggered,
        ...(typeof f.cvss === 'number' && f.cvss > 0
          ? { 'auditforge/cvss': String(f.cvss) }
          : {}),
        ...(f.cve ? { 'auditforge/cve': f.cve } : {}),
        'auditforge/detectedAt': f.createdAt.toISOString(),
      },
    }
  })

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'AuditForge',
            organization: 'AuditForge',
            informationUri: 'https://auditforge.aenews.online',
            version: process.env.APP_VERSION ?? '2.0.0',
            semanticVersion: process.env.APP_VERSION ?? '2.0.0',
            rules,
          },
        },
        automationDetails: {
          id: `auditforge/${scanTool ? scanTool.toLowerCase() : 'campaign'}/${new Date()
            .toISOString()
            .slice(0, 10)}`,
          description: { text: `Export AuditForge — ${campaignName}` },
        },
        results,
      },
    ],
    _meta: {
      campaign: { name: campaignName, target: campaignTarget },
      counts: { findings: results.length, rules: rules.length },
      format: 'SARIF 2.1.0 (OASIS) — GitHub Code Scanning compatible',
    },
  }
}

export const GET = withApi(async (req: NextRequest) => {
  const session = await requireAuth(['AUDITOR', 'ADMIN'])
  if (session instanceof NextResponse) return session

  const campaignId = req.nextUrl.searchParams.get('campaignId') ?? ''
  const scanId = req.nextUrl.searchParams.get('scanId') ?? ''
  const includeResolved = req.nextUrl.searchParams.get('includeResolved') === 'true'
  if (!campaignId && !scanId) {
    return NextResponse.json(
      { error: 'Paramètre campaignId ou scanId requis' },
      { status: 400 }
    )
  }

  const doc = await buildSarifDocument(
    campaignId ? { campaignId } : { scanId },
    includeResolved
  )
  if (!doc) {
    return NextResponse.json({ error: 'Campagne ou scan introuvable' }, { status: 404 })
  }

  await writeAudit(
    session.username,
    'REPORT_SARIF_EXPORT',
    doc._meta.campaign.name,
    `Export SARIF 2.1.0 — ${doc._meta.counts.findings} constat(s), ${doc._meta.counts.rules} règle(s)`
  )

  const safeName = doc._meta.campaign.name.replace(/[^\w.-]+/g, '_').slice(0, 80) || 'export'
  return new NextResponse(JSON.stringify(doc, null, 2), {
    status: 200,
    headers: {
      'Content-Type': 'application/sarif+json; charset=utf-8',
      'Content-Disposition': `attachment; filename="auditforge-sarif-${safeName}.sarif"`,
      'Cache-Control': 'no-store',
    },
  })
})
