/**
 * POST /api/campaigns/[id]/launch — (ré-)exécuter des outils sur une campagne
 * (contrat worklog §F.10 ; sémantique corrigée §L.8)
 *
 * body {tools:Tool[]} (1 à 4 outils) :
 * - 409 si un outil DEMANDÉ a déjà un scan actif (QUEUED/RUNNING) sur la campagne ;
 * - sinon crée un NOUVEAU scan QUEUED pour CHAQUE outil demandé (ré-exécution,
 *   même si des scans finis de cet outil existent) + campagne → RUNNING ;
 * - appels moteur en Promise.allSettled : seuls les scans dont l'appel a échoué
 *   passent FAILED ; campagne FAILED uniquement si TOUS ont échoué (sinon RUNNING) ;
 * - warning si au moins un échec.
 * Le tout sous verrou applicatif par campagne (src/lib/mutex.ts).
 */
import { NextRequest, NextResponse } from 'next/server'
import { z } from 'zod'
import { db } from '@/lib/db'
import { requireAuth } from '@/lib/auth'
import { writeAudit } from '@/lib/audit'
import { engineRun } from '@/lib/engine-client'
import { TOOLS, isToolCompatible, toCampaignDTO } from '@/lib/dto'
import { withCampaignLock } from '@/lib/mutex'
import { withApi } from '@/lib/route-handler'
import type { Profile, TargetType, Tool } from '@/lib/types'

export const dynamic = 'force-dynamic'

const launchSchema = z.object({
  tools: z.array(z.enum(TOOLS)).min(1).max(4),
})

export const POST = withApi<{ id: string }>(async (req, { params }) => {
  const session = await requireAuth(['AUDITOR', 'ADMIN'])
  if (session instanceof NextResponse) return session

  const { id } = await params

  const raw = await req.json().catch(() => null)
  const parsed = launchSchema.safeParse(raw)
  if (!parsed.success) {
    return NextResponse.json({ error: 'Outils invalides — tableau de 1 à 4 outils requis' }, { status: 400 })
  }
  const tools: Tool[] = parsed.data.tools
  if (new Set(tools).size !== tools.length) {
    return NextResponse.json({ error: 'Les outils doivent être uniques' }, { status: 400 })
  }

  let warning: string | undefined
  const guard = await withCampaignLock(id, async (): Promise<NextResponse | null> => {
    const campaign = await db.campaign.findUnique({ where: { id } })
    if (!campaign) {
      return NextResponse.json({ error: 'Campagne introuvable' }, { status: 404 })
    }

    // Compatibilité outil ⇄ type de cible de la campagne (worklog §B)
    const targetType = campaign.targetType as TargetType
    const incompatible = tools.find((tool) => !isToolCompatible(tool, targetType))
    if (incompatible) {
      return NextResponse.json(
        { error: `Outil ${incompatible} incompatible avec une cible de type ${campaign.targetType}` },
        { status: 400 }
      )
    }

    // Un seul lot de scans actif à la fois : un outil demandé ne doit pas avoir
    // de scan QUEUED/RUNNING sur cette campagne (§L.8).
    const activeForTools = await db.scan.findMany({
      where: { campaignId: id, tool: { in: tools }, status: { in: ['QUEUED', 'RUNNING'] } },
      select: { tool: true },
    })
    if (activeForTools.length > 0) {
      const tool = activeForTools[0].tool
      return NextResponse.json(
        { error: `Un scan ${tool} est déjà en cours pour cette campagne` },
        { status: 409 }
      )
    }

    // Ré-exécution (§L.8) : un NOUVEAU scan QUEUED par outil demandé, même si des
    // scans finis (COMPLETED/FAILED/CANCELLED) de cet outil existent déjà.
    const { scans } = await db.$transaction(async (tx) => {
      const createdScans: { id: string; tool: string }[] = []
      for (const tool of tools) {
        const scan = await tx.scan.create({
          data: {
            campaignId: id,
            tool,
            target: campaign.target,
            status: 'QUEUED',
            progress: 0,
            phase: '',
          },
          select: { id: true, tool: true },
        })
        createdScans.push(scan)
      }
      await tx.campaign.update({ where: { id }, data: { status: 'RUNNING' } })
      return { scans: createdScans }
    })

    // Appels moteur tolérants (§L.9) : allSettled, seuls les échecs passent FAILED.
    const results = await Promise.allSettled(
      scans.map((scan) =>
        engineRun({
          scanId: scan.id,
          tool: scan.tool as Tool,
          target: campaign.target,
          targetType,
          profile: campaign.profile as Profile,
        })
      )
    )
    const failedIds = scans
      .filter((_, i) => results[i].status === 'rejected')
      .map((s) => s.id)
    if (failedIds.length > 0) {
      await db.scan.updateMany({
        where: { id: { in: failedIds } },
        data: { status: 'FAILED', finishedAt: new Date(), durationMs: 0 },
      })
    }
    const allFailed = failedIds.length === scans.length
    if (allFailed) {
      await db.campaign.update({ where: { id }, data: { status: 'FAILED' } })
      warning = "Moteur d'exécution indisponible — scans marqués en échec."
    } else if (failedIds.length > 0) {
      warning = "Moteur d'exécution indisponible pour certains scans."
    }
    await writeAudit(session.username, 'CAMPAIGN_LAUNCH', campaign.name, warning ?? tools.join(', '))
    return null
  })

  if (guard instanceof NextResponse) return guard

  const fresh = await db.campaign.findUnique({
    where: { id },
    include: {
      createdBy: { select: { username: true } },
      scans: { orderBy: { createdAt: 'asc' } },
    },
  })
  if (!fresh) {
    return NextResponse.json({ error: 'Campagne introuvable' }, { status: 500 })
  }
  return NextResponse.json({ campaign: toCampaignDTO(fresh), warning })
})
