/**
 * AuditForge — extraction de l'IP cliente (F-06, audit 8-a).
 *
 * 1. `cf-connecting-ip` — posé par Cloudflare (production), non falsifiable
 *    côté client ;
 * 2. sinon le DERNIER élément de `x-forwarded-for` : c'est l'IP ajoutée par le
 *    proxy de confiance le plus proche de nous (le PREMIER élément est celui du
 *    client et peut être usurpé pour contourner le blocage par IP) ;
 * 3. sinon 'local' (accès direct en développement).
 *
 * Usage : clé de rate-limiting et journal d'audit — jamais pour autoriser ou
 * refuser une session.
 */
import type { NextRequest } from 'next/server'

export function clientIp(req: NextRequest): string {
  const cf = req.headers.get('cf-connecting-ip')?.trim()
  if (cf) return cf
  const xff = (req.headers.get('x-forwarded-for') ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
  return xff[xff.length - 1] ?? 'local'
}
