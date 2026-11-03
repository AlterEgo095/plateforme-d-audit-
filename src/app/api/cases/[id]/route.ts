/**
 * /api/cases/[id] — Sprint 2 : détail d'un dossier client.
 *
 * GET   : toute session authentifiée — dossier + historique COMPLET des
 *         autorisations (traçabilité) + campagnes rattachées (résumés).
 * PATCH : AUDITOR+ — édition { title?, contact?, description? } et/ou
 *         { status: OPEN | CLOSED } (les autres statuts sont dérivés du
 *         workflow : AUTHORIZED/RUNNING/REPORTED posés par les actions).
 *         Clôturer = plus aucun lancement possible via le garde case-auth.
 */
import { NextRequest, NextResponse } from 'next/server'
import { z } from 'zod'
import { db } from '@/lib/db'
import { requireAuth } from '@/lib/auth'
import { writeAudit } from '@/lib/audit'
import { toAuthorizationDTO, toCaseDTO } from '@/lib/dto'
import { withApi } from '@/lib/route-handler'
import type { Profile, TargetType } from '@/lib/types'

export const dynamic = 'force-dynamic'

/** Campagne résumée du détail (même forme que le rapport client). */
function campaignSummary(c: {
  id: string
  name: string
  target: string
  targetType: string
  profile: string
  status: string
  createdAt: Date
  scans: {
    id: string
    tool: string
    status: string
    mode: string | null
    progress: number
    phase: string
    startedAt: Date | null
    finishedAt: Date | null
    durationMs: number | null
    findingsCount: number
    criticalCount: number
    createdAt: Date
  }[]
}) {
  return {
    id: c.id,
    name: c.name,
    target: c.target,
    targetType: c.targetType as TargetType,
    profile: c.profile as Profile,
    status: c.status,
    createdAt: c.createdAt.toISOString(),
    scans: c.scans.map((s) => ({
      id: s.id,
      campaignId: c.id,
      tool: s.tool,
      target: c.target,
      status: s.status,
      mode: (s.mode as 'REAL' | 'SIMULATION' | null) ?? null,
      progress: s.progress,
      phase: s.phase,
      startedAt: s.startedAt ? s.startedAt.toISOString() : null,
      finishedAt: s.finishedAt ? s.finishedAt.toISOString() : null,
      durationMs: s.durationMs,
      findingsCount: s.findingsCount,
      criticalCount: s.criticalCount,
      createdAt: s.createdAt.toISOString(),
    })),
  }
}

// ─── GET /api/cases/[id] ─────────────────────────────────────────────

export const GET = withApi<{ id: string }>(async (_req, { params }) => {
  const session = await requireAuth()
  if (session instanceof NextResponse) return session

  const { id } = await params
  const kase = await db.case.findUnique({
    where: { id },
    include: {
      createdBy: { select: { username: true } },
      authorizations: { orderBy: { signedAt: 'desc' } },
      campaigns: {
        orderBy: { createdAt: 'desc' },
        take: 100,
        include: { scans: { orderBy: { createdAt: 'asc' } } },
      },
    },
  })
  if (!kase) {
    return NextResponse.json({ error: 'Dossier introuvable' }, { status: 404 })
  }

  return NextResponse.json({
    case: toCaseDTO(kase),
    authorizationHistory: kase.authorizations.map(toAuthorizationDTO),
    campaigns: kase.campaigns.map(campaignSummary),
  })
})

// ─── PATCH /api/cases/[id] ───────────────────────────────────────────

const patchSchema = z.object({
  title: z.string().min(3).max(120).optional(),
  contact: z.string().max(160).optional(),
  description: z.string().max(1000).optional(),
  status: z.enum(['OPEN', 'CLOSED']).optional(),
})

export const PATCH = withApi<{ id: string }>(async (req, { params }) => {
  const session = await requireAuth(['AUDITOR', 'ADMIN'])
  if (session instanceof NextResponse) return session

  const { id } = await params
  const raw = await req.json().catch(() => null)
  const parsed = patchSchema.safeParse(raw)
  if (!parsed.success) {
    return NextResponse.json(
      { error: 'Corps invalide — { title?, contact?, description?, status?: OPEN|CLOSED } attendu' },
      { status: 400 }
    )
  }
  const input = parsed.data
  if (Object.keys(input).length === 0) {
    return NextResponse.json({ error: 'Aucun champ à mettre à jour' }, { status: 400 })
  }

  const existing = await db.case.findUnique({ where: { id } })
  if (!existing) {
    return NextResponse.json({ error: 'Dossier introuvable' }, { status: 404 })
  }

  const updated = await db.case.update({
    where: { id },
    data: {
      ...(input.title !== undefined ? { title: input.title.trim() } : {}),
      ...(input.contact !== undefined ? { contact: input.contact.trim() || null } : {}),
      ...(input.description !== undefined
        ? { description: input.description.trim() || null }
        : {}),
      ...(input.status !== undefined ? { status: input.status } : {}),
    },
    include: { createdBy: { select: { username: true } }, authorizations: true },
  })

  await writeAudit(
    session.username,
    input.status === 'CLOSED' ? 'CASE_CLOSE' : 'CASE_UPDATE',
    updated.reference,
    input.status
      ? `Statut → ${updated.status}`
      : `Édition des métadonnées${input.title !== undefined ? ` — titre « ${updated.title} »` : ''}`
  )
  return NextResponse.json({ case: toCaseDTO(updated) })
})
