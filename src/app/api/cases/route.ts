/**
 * /api/cases — Sprint 2 : dossiers client (Case) — liste et création.
 *
 * GET  : toute session authentifiée — dossiers (take 100) avec compteurs
 *        agrégés (scans des campagnes rattachées) et autorisation active.
 * POST : AUDITOR+ — création { title, client, contact?, description? } ;
 *        référence client auto-générée AF-<année>-<NNN> (séquence annuelle,
 *        retry sur collision unique). Trace CASE_CREATE.
 */
import { NextRequest, NextResponse } from 'next/server'
import { z } from 'zod'
import { db } from '@/lib/db'
import { requireAuth } from '@/lib/auth'
import { writeAudit } from '@/lib/audit'
import { toCaseDTO } from '@/lib/dto'
import { caseReferenceForYear, countCasesForYear } from '@/lib/case-auth'
import { withApi } from '@/lib/route-handler'

export const dynamic = 'force-dynamic'

// ─── GET /api/cases ──────────────────────────────────────────────────

export const GET = withApi(async () => {
  const session = await requireAuth()
  if (session instanceof NextResponse) return session

  const cases = await db.case.findMany({
    orderBy: { createdAt: 'desc' },
    take: 100,
    include: {
      createdBy: { select: { username: true } },
      authorizations: { orderBy: { signedAt: 'desc' } },
      _count: { select: { campaigns: true } },
    },
  })

  // Compteurs exacts (findings/critiques) via les scans des campagnes.
  const caseIds = cases.map((c) => c.id)
  const campaignSums = await db.scan.groupBy({
    by: ['campaignId'],
    where: caseIds.length > 0 ? { campaign: { caseId: { in: caseIds } } } : undefined,
    _sum: { findingsCount: true, criticalCount: true },
  })
  const campaigns = caseIds.length
    ? await db.campaign.findMany({
        where: { caseId: { in: caseIds } },
        select: { id: true, caseId: true },
      })
    : []
  const sumsByCampaign = new Map(campaignSums.map((s) => [s.campaignId, s._sum]))
  const sumsByCase = new Map<string, { findings: number; critical: number }>()
  for (const c of campaigns) {
    if (!c.caseId) continue
    const sum = sumsByCampaign.get(c.id)
    const acc = sumsByCase.get(c.caseId) ?? { findings: 0, critical: 0 }
    acc.findings += sum?.findingsCount ?? 0
    acc.critical += sum?.criticalCount ?? 0
    sumsByCase.set(c.caseId, acc)
  }

  return NextResponse.json({
    cases: cases.map((c) => {
      const dto = toCaseDTO(c)
      const sums = sumsByCase.get(c.id)
      return {
        ...dto,
        findingsCount: sums?.findings ?? 0,
        criticalCount: sums?.critical ?? 0,
      }
    }),
  })
})

// ─── POST /api/cases ─────────────────────────────────────────────────

const createSchema = z.object({
  title: z.string().min(3).max(120),
  client: z.string().min(2).max(120),
  contact: z.string().max(160).optional(),
  description: z.string().max(1000).optional(),
})

export const POST = withApi(async (req: NextRequest) => {
  const session = await requireAuth(['AUDITOR', 'ADMIN'])
  if (session instanceof NextResponse) return session

  const raw = await req.json().catch(() => null)
  const parsed = createSchema.safeParse(raw)
  if (!parsed.success) {
    const msg = parsed.error.issues
      .map((i) => `${i.path.join('.') || 'corps'} : ${i.message}`)
      .join(' ; ')
    return NextResponse.json({ error: `Données invalides — ${msg}` }, { status: 400 })
  }
  const input = parsed.data

  // Référence AF-<année>-<NNN> : séquence annuelle + retry sur collision
  // (créations concurrentes) — max 50 tentatives.
  const year = new Date().getUTCFullYear()
  let sequence = (await countCasesForYear(year)) + 1
  let created: Awaited<ReturnType<typeof db.case.create>> | null = null
  for (let attempt = 0; attempt < 50; attempt++) {
    const reference = caseReferenceForYear(year, sequence)
    try {
      created = await db.case.create({
        data: {
          reference,
          title: input.title.trim(),
          client: input.client.trim(),
          contact: input.contact?.trim() || null,
          description: input.description?.trim() || null,
          status: 'OPEN',
          createdById: session.sub,
        },
        include: { createdBy: { select: { username: true } }, authorizations: true },
      })
      break
    } catch (error) {
      // P2002 = violation d'unicité (référence prise par une création concurrente).
      const code = (error as { code?: string }).code
      if (code !== 'P2002') throw error
      sequence += 1
    }
  }
  if (!created) {
    return NextResponse.json(
      { error: 'Impossible de générer une référence unique — réessayez' },
      { status: 500 }
    )
  }

  await writeAudit(
    session.username,
    'CASE_CREATE',
    created.reference,
    `Dossier « ${created.title} » — client ${created.client}`
  )
  return NextResponse.json({ case: toCaseDTO(created) }, { status: 201 })
})
