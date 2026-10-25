/**
 * /api/campaigns — liste et création de campagnes (contrats worklog §F.6, §F.7 ; §L.9/10/13)
 * GET  : toute session authentifiée (statuts recalculés paresseusement, take 100 / scans 50)
 * POST : AUDITOR+ — validation zod + compatibilité outils ⇄ cibles (§B),
 *        création campagne+scans en $transaction, lancement via Promise.allSettled
 *        (seuls les scans dont l'appel moteur a échoué passent FAILED) sous verrou par campagne.
 */
import { NextRequest, NextResponse } from 'next/server'
import { z } from 'zod'
import { db } from '@/lib/db'
import { requireAuth } from '@/lib/auth'
import { writeAudit } from '@/lib/audit'
import { engineRun } from '@/lib/engine-client'
import { refreshCampaignStatuses } from '@/lib/campaign-status'
import { PROFILES, TARGET_TYPES, TOOLS, isToolCompatible, toCampaignDTO, validateTarget } from '@/lib/dto'
import { withCampaignLock } from '@/lib/mutex'
import { withApi } from '@/lib/route-handler'
import type { Profile, Tool } from '@/lib/types'

export const dynamic = 'force-dynamic'

// ─── GET /api/campaigns ──────────────────────────────────────────────

export const GET = withApi(async () => {
  const session = await requireAuth()
  if (session instanceof NextResponse) return session

  await refreshCampaignStatuses()

  const campaigns = await db.campaign.findMany({
    orderBy: { createdAt: 'desc' },
    take: 100,
    include: {
      createdBy: { select: { username: true } },
      scans: { orderBy: { createdAt: 'asc' }, take: 50 },
      _count: { select: { scans: true } },
    },
  })
  // m9 (audit 8-a) : totaux EXACTS (au-delà des 50 scans inclus) via agrégats.
  const totals = await db.scan.groupBy({
    by: ['campaignId'],
    where: { campaignId: { in: campaigns.map((c) => c.id) } },
    _sum: { findingsCount: true, criticalCount: true },
  })
  const totalsByCampaign = new Map(totals.map((t) => [t.campaignId, t._sum]))
  return NextResponse.json({
    campaigns: campaigns.map((c) =>
      toCampaignDTO(c, {
        scansCount: c._count.scans,
        findingsCount: totalsByCampaign.get(c.id)?.findingsCount ?? 0,
        criticalCount: totalsByCampaign.get(c.id)?.criticalCount ?? 0,
      })
    ),
  })
})

// ─── POST /api/campaigns ─────────────────────────────────────────────

const createSchema = z.object({
  name: z.string().min(3).max(120),
  description: z.string().max(500).optional(),
  target: z.string().min(1).max(300),
  targetType: z.enum(TARGET_TYPES),
  profile: z.enum(PROFILES),
  tools: z.array(z.enum(TOOLS)).min(1).max(4),
  launchNow: z.boolean(),
})

/** Message d'erreur de validation zod compact (français). */
function zodError(error: z.ZodError): string {
  return error.issues
    .map((issue) => `${issue.path.join('.') || 'corps'} : ${issue.message}`)
    .join(' ; ')
}

export const POST = withApi(async (req: NextRequest) => {
  const session = await requireAuth(['AUDITOR', 'ADMIN'])
  if (session instanceof NextResponse) return session

  const raw = await req.json().catch(() => null)
  const parsed = createSchema.safeParse(raw)
  if (!parsed.success) {
    return NextResponse.json({ error: `Données invalides — ${zodError(parsed.error)}` }, { status: 400 })
  }
  const input = parsed.data

  if (new Set(input.tools).size !== input.tools.length) {
    return NextResponse.json({ error: 'Les outils doivent être uniques' }, { status: 400 })
  }
  // Compatibilité outil ⇄ type de cible (worklog §B)
  const incompatible = input.tools.find((tool) => !isToolCompatible(tool, input.targetType))
  if (incompatible) {
    return NextResponse.json(
      { error: `Outil ${incompatible} incompatible avec une cible de type ${input.targetType}` },
      { status: 400 }
    )
  }

  // C1 (audit 8-a) : schéma strict par type de cible — bloque l'injection
  // d'options/transport dans les CLI du moteur (git clone, phantom…).
  const targetError = validateTarget(input.targetType, input.target)
  if (targetError) {
    return NextResponse.json({ error: targetError }, { status: 400 })
  }

  // Création atomique campagne + scans (§L.10) — la transaction ne contient que des écritures DB.
  const target = input.target.trim()
  const { campaign, scans } = await db.$transaction(async (tx) => {
    const created = await tx.campaign.create({
      data: {
        name: input.name.trim(),
        description: input.description ?? null,
        target,
        targetType: input.targetType,
        profile: input.profile,
        status: 'DRAFT',
        createdById: session.sub,
      },
    })
    const createdScans: { id: string; tool: string }[] = []
    if (input.launchNow) {
      for (const tool of input.tools) {
        const scan = await tx.scan.create({
          data: {
            campaignId: created.id,
            tool,
            target,
            status: 'QUEUED',
            progress: 0,
            phase: '',
          },
          select: { id: true, tool: true },
        })
        createdScans.push(scan)
      }
    }
    return { campaign: created, scans: createdScans }
  })

  await writeAudit(
    session.username,
    'CAMPAIGN_CREATE',
    campaign.name,
    `Cible ${campaign.target} (${campaign.profile}, ${campaign.targetType})`
  )

  // Lancement immédiat : appels moteur sous verrou applicatif par campagne (§L.8/§L.9)
  let warning: string | undefined
  if (input.launchNow) {
    warning = await withCampaignLock(campaign.id, async () => {
      const results = await Promise.allSettled(
        scans.map((scan) =>
          engineRun({
            scanId: scan.id,
            tool: scan.tool as Tool,
            target,
            targetType: input.targetType,
            profile: input.profile,
          })
        )
      )
      const failedIds = scans
        .filter((_, i) => results[i].status === 'rejected')
        .map((s) => s.id)
      // i1 (audit 8-a) : motifs distincts des échecs — le message réel du
      // moteur (ex. « Trop de scans simultanés ») remonte à l'utilisateur.
      const launchReasons = Array.from(
        new Set(
          results
            .filter((r): r is PromiseRejectedResult => r.status === 'rejected')
            .map((r) => (r.reason instanceof Error ? r.reason.message : String(r.reason)))
        )
      ).slice(0, 2)
      const reasonSuffix =
        launchReasons.length > 0 ? ` — ${launchReasons.join(' ; ').slice(0, 300)}` : ''
      if (failedIds.length > 0) {
        // Seuls les scans dont l'appel moteur a échoué sont marqués FAILED.
        await db.scan.updateMany({
          where: { id: { in: failedIds } },
          data: { status: 'FAILED', finishedAt: new Date(), durationMs: 0 },
        })
      }
      // Campagne FAILED uniquement si TOUS les appels ont échoué, sinon RUNNING.
      const allFailed = failedIds.length === scans.length
      await db.campaign.update({
        where: { id: campaign.id },
        data: { status: allFailed ? 'FAILED' : 'RUNNING' },
      })

      if (allFailed) {
        const msg = `Lancement impossible — scans marqués en échec${reasonSuffix}`
        await writeAudit(session.username, 'CAMPAIGN_LAUNCH', campaign.name, msg)
        return msg
      }
      if (failedIds.length > 0) {
        const msg = `Lancement impossible pour certains scans${reasonSuffix}`
        await writeAudit(
          session.username,
          'CAMPAIGN_LAUNCH',
          campaign.name,
          `${input.tools.join(', ')} — ${msg}`
        )
        return msg
      }
      await writeAudit(session.username, 'CAMPAIGN_LAUNCH', campaign.name, input.tools.join(', '))
      return undefined
    })
  }

  const fresh = await db.campaign.findUnique({
    where: { id: campaign.id },
    include: {
      createdBy: { select: { username: true } },
      scans: { orderBy: { createdAt: 'asc' } },
    },
  })
  if (!fresh) {
    return NextResponse.json({ error: 'Campagne introuvable après création' }, { status: 500 })
  }
  return NextResponse.json({ campaign: toCampaignDTO(fresh), warning }, { status: 201 })
})
