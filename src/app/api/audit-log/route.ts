/**
 * GET /api/audit-log — journal d'audit (contrat worklog §F.18)
 * ?limit=<200> (max 500) → {entries:AuditEntry[]} triées desc par id.
 */
import { NextRequest, NextResponse } from 'next/server'
import { db } from '@/lib/db'
import { requireAuth } from '@/lib/auth'
import { toAuditDTO } from '@/lib/dto'
import { withApi } from '@/lib/route-handler'

export const dynamic = 'force-dynamic'

const MAX_LIMIT = 500
const DEFAULT_LIMIT = 200

export const GET = withApi(async (req: NextRequest) => {
  const session = await requireAuth()
  if (session instanceof NextResponse) return session

  const requested =
    Number.parseInt(req.nextUrl.searchParams.get('limit') ?? String(DEFAULT_LIMIT), 10) || DEFAULT_LIMIT
  const limit = Math.min(MAX_LIMIT, Math.max(1, requested))

  const entries = await db.auditTrail.findMany({ orderBy: { id: 'desc' }, take: limit })
  return NextResponse.json({ entries: entries.map(toAuditDTO) })
})
