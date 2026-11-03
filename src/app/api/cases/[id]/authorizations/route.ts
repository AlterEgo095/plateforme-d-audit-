/**
 * /api/cases/[id]/authorizations — Sprint 2 : signature d'une autorisation.
 *
 * POST : AUDITOR+ — { signatory, signatoryRole, scope, targets: string[],
 *         validFrom?, validUntil } → attestation enregistrée avec empreinte
 *         SHA-256 canonique (case-auth.authorizationSignature). La cible de
 *         toute campagne du dossier devra appartenir à `targets` (hôte exact
 *         ou joker *.domaine). Le dossier OPEN passe AUTHORIZED. Trace
 *         CASE_AUTHORIZATION_SIGN.
 */
import { NextRequest, NextResponse } from 'next/server'
import { z } from 'zod'
import { db } from '@/lib/db'
import { requireAuth } from '@/lib/auth'
import { writeAudit } from '@/lib/audit'
import { toAuthorizationDTO } from '@/lib/dto'
import { authorizationSignature, type AuthorizationPayload } from '@/lib/case-auth'
import { withApi } from '@/lib/route-handler'

export const dynamic = 'force-dynamic'

/**
 * Format d'un hôte autorisé : nom d'hôte (labels alphanumériques + tirets,
 * TLD lettres) ou joker « *.domaine ». Rejet explicite de tout le reste
 * (pas d'IP plage, pas de chemin, pas d'URL — le périmètre est par HÔTE).
 */
const TARGET_ENTRY_RE = /^(?:\*\.)?[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$/

const signSchema = z.object({
  signatory: z.string().min(2).max(120),
  signatoryRole: z.string().min(2).max(120),
  scope: z.string().min(5).max(1000),
  targets: z.array(z.string().min(3).max(120)).min(1).max(20),
  validFrom: z.string().datetime({ offset: true }).optional(),
  validUntil: z.string().datetime({ offset: true }),
})

export const POST = withApi<{ id: string }>(async (req, { params }) => {
  const session = await requireAuth(['AUDITOR', 'ADMIN'])
  if (session instanceof NextResponse) return session

  const { id } = await params
  const raw = await req.json().catch(() => null)
  const parsed = signSchema.safeParse(raw)
  if (!parsed.success) {
    const msg = parsed.error.issues
      .map((i) => `${i.path.join('.') || 'corps'} : ${i.message}`)
      .join(' ; ')
    return NextResponse.json({ error: `Données invalides — ${msg}` }, { status: 400 })
  }
  const input = parsed.data

  // Normalisation des hôtes (minuscules, sans point final, déduplication).
  const targets = Array.from(
    new Set(
      input.targets
        .map((t) => t.trim().toLowerCase().replace(/\.$/, ''))
        .filter(Boolean)
    )
  )
  if (targets.length === 0) {
    return NextResponse.json({ error: 'Au moins un hôte autorisé est requis' }, { status: 400 })
  }
  const invalid = targets.find((t) => !TARGET_ENTRY_RE.test(t))
  if (invalid) {
    return NextResponse.json(
      {
        error:
          `Hôte « ${invalid} » invalide — attendu un nom d'hôte (example.com) ou un joker ` +
          '(*.example.com) ; ni IP, ni URL, ni chemin',
      },
      { status: 400 }
    )
  }

  const kase = await db.case.findUnique({ where: { id } })
  if (!kase) {
    return NextResponse.json({ error: 'Dossier introuvable' }, { status: 404 })
  }
  if (kase.status === 'CLOSED') {
    return NextResponse.json(
      { error: `Dossier ${kase.reference} clôturé — autorisation impossible` },
      { status: 409 }
    )
  }

  const validFrom = input.validFrom ? new Date(input.validFrom) : new Date()
  const validUntil = new Date(input.validUntil)
  if (Number.isNaN(validFrom.getTime()) || Number.isNaN(validUntil.getTime())) {
    return NextResponse.json({ error: 'Dates de validité invalides' }, { status: 400 })
  }
  if (validUntil.getTime() <= validFrom.getTime()) {
    return NextResponse.json(
      { error: 'validUntil doit être postérieur à validFrom' },
      { status: 400 }
    )
  }
  if (validUntil.getTime() <= Date.now()) {
    return NextResponse.json(
      { error: 'La période d’autorisation doit se terminer dans le futur' },
      { status: 400 }
    )
  }

  // Empreinte canonique (caseReference + champs + hôtes normalisés) — la
  // ré-émission avec un champ modifié produirait une empreinte différente.
  const payload: AuthorizationPayload = {
    caseReference: kase.reference,
    caseTitle: kase.title,
    client: kase.client,
    signatory: input.signatory.trim(),
    signatoryRole: input.signatoryRole.trim(),
    scope: input.scope.trim(),
    targets,
    validFrom: validFrom.toISOString(),
    validUntil: validUntil.toISOString(),
  }
  const signature = authorizationSignature(payload)

  const [authorization, updatedCase] = await db.$transaction(async (tx) => {
    const auth = await tx.caseAuthorization.create({
      data: {
        caseId: id,
        signatory: payload.signatory,
        signatoryRole: payload.signatoryRole,
        scope: payload.scope,
        targets: JSON.stringify(targets),
        validFrom,
        validUntil,
        signature,
        signedAt: new Date(),
      },
    })
    const k =
      kase.status === 'OPEN'
        ? await tx.case.update({ where: { id }, data: { status: 'AUTHORIZED' } })
        : kase
    return [auth, k] as const
  })

  await writeAudit(
    session.username,
    'CASE_AUTHORIZATION_SIGN',
    updatedCase.reference,
    `Autorisation signée par ${payload.signatory} (${payload.signatoryRole}) — ` +
      `${targets.length} hôte(s) : ${targets.slice(0, 5).join(', ')} — jusqu'au ${validUntil.toISOString().slice(0, 10)}`
  )
  return NextResponse.json({ authorization: toAuthorizationDTO(authorization) }, { status: 201 })
})
