/**
 * GET /api/findings — recherche de constats (contrat worklog §F.15 ; §L.13)
 * Filtres CSV ?severity= &tool= &status=, ?scanId=, recherche plein-texte ?q=
 * (max 200 caractères, caractères % _ \ neutralisés).
 * Tri : sévérité desc (CRITICAL d'abord) puis createdAt desc, max 500.
 * SQL borné : take 2000 (createdAt desc) puis tri JS et slice 500.
 */
import { NextRequest, NextResponse } from 'next/server'
import { z } from 'zod'
import { db } from '@/lib/db'
import { requireAuth } from '@/lib/auth'
import { FINDING_STATUSES, SEVERITIES, TOOLS, parseCsvParam, sortFindings, toFindingDTO } from '@/lib/dto'
import { withApi } from '@/lib/route-handler'

export const dynamic = 'force-dynamic'

const MAX_RESULTS = 500
const SQL_TAKE = 2000

// Recherche plein-texte : longueur bornée, caractères joker/échappement LIKE neutralisés (§L.13).
const qSchema = z
  .string()
  .max(200)
  .trim()
  .transform((v) => v.replace(/[%_\\]/g, ' '))
  .optional()

export const GET = withApi(async (req: NextRequest) => {
  const session = await requireAuth()
  if (session instanceof NextResponse) return session

  const searchParams = req.nextUrl.searchParams
  const severities = parseCsvParam(searchParams.get('severity'), SEVERITIES)
  if (severities === 'invalid') {
    return NextResponse.json(
      { error: 'Sévérité invalide — valeurs autorisées : CRITICAL, HIGH, MEDIUM, LOW, INFO' },
      { status: 400 }
    )
  }
  const tools = parseCsvParam(searchParams.get('tool'), TOOLS)
  if (tools === 'invalid') {
    return NextResponse.json(
      { error: 'Outil invalide — valeurs autorisées : PHANTOM, DEEPAUDIT, BASALT, REDAMON' },
      { status: 400 }
    )
  }
  const statuses = parseCsvParam(searchParams.get('status'), FINDING_STATUSES)
  if (statuses === 'invalid') {
    return NextResponse.json(
      { error: 'Statut invalide — valeurs autorisées : OPEN, CONFIRMED, FALSE_POSITIVE, FIXED' },
      { status: 400 }
    )
  }
  const scanId = searchParams.get('scanId')?.trim() || null
  const q = qSchema.safeParse(searchParams.get('q') ?? undefined)
  if (!q.success) {
    return NextResponse.json({ error: 'Recherche invalide — 200 caractères maximum' }, { status: 400 })
  }
  const search = q.data

  // `contains` seul : SQLite (LIKE) est insensible à la casse pour l'ASCII.
  const rows = await db.finding.findMany({
    where: {
      ...(severities ? { severity: { in: severities } } : {}),
      ...(tools ? { tool: { in: tools } } : {}),
      ...(statuses ? { status: { in: statuses } } : {}),
      ...(scanId ? { scanId } : {}),
      ...(search
        ? {
            OR: [
              { title: { contains: search } },
              { description: { contains: search } },
              { location: { contains: search } },
              { category: { contains: search } },
            ],
          }
        : {}),
    },
    orderBy: { createdAt: 'desc' },
    take: SQL_TAKE,
  })

  const findings = sortFindings(rows).slice(0, MAX_RESULTS).map(toFindingDTO)
  return NextResponse.json({ findings })
})
