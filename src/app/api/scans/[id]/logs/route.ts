/**
 * GET /api/scans/[id]/logs — flux de logs d'un scan (contrat worklog §F.13)
 * ?after=<id connu>&limit=<200> → {logs:LogEntry[]} triés asc (mode polling)
 */
import { NextRequest, NextResponse } from 'next/server'
import { db } from '@/lib/db'
import { requireAuth } from '@/lib/auth'
import { toLogDTO } from '@/lib/dto'
import { withApi } from '@/lib/route-handler'

export const dynamic = 'force-dynamic'

const MAX_LIMIT = 500
const DEFAULT_LIMIT = 200

export const GET = withApi<{ id: string }>(async (req, { params }) => {
  const session = await requireAuth()
  if (session instanceof NextResponse) return session

  const { id } = await params
  const scan = await db.scan.findUnique({ where: { id }, select: { id: true } })
  if (!scan) {
    return NextResponse.json({ error: 'Scan introuvable' }, { status: 404 })
  }

  const searchParams = req.nextUrl.searchParams
  const after = Math.max(0, Number.parseInt(searchParams.get('after') ?? '0', 10) || 0)
  const requested = Number.parseInt(searchParams.get('limit') ?? String(DEFAULT_LIMIT), 10) || DEFAULT_LIMIT
  const limit = Math.min(MAX_LIMIT, Math.max(1, requested))

  const logs = await db.scanLog.findMany({
    where: { scanId: id, id: { gt: after } },
    orderBy: { id: 'asc' },
    take: limit,
  })
  return NextResponse.json({ logs: logs.map(toLogDTO) })
})
