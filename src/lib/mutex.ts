/**
 * AuditForge — Verrou applicatif par campagne (contrat worklog §L.8)
 *
 * Sérialise les sections critiques (lancement de scans) par campagne afin
 * d'éliminer les conditions de course (TOCTOU) entre POST /api/campaigns
 * (launchNow) et POST /api/campaigns/[id]/launch.
 *
 * Implémentation : Map<campaignId, Promise> en chaîne — chaque entrant s'accroche
 * à la promesse du précédent ; le verrou est TOUJOURS libéré (finally).
 */

const g = globalThis as unknown as {
  __afCampaignLocks?: Map<string, Promise<unknown>>
}

const locks: Map<string, Promise<unknown>> = (g.__afCampaignLocks ??= new Map())

/**
 * Exécute `fn` en exclusivité mutuelle pour la campagne donnée.
 * Les appels concurrents pour la même campagne sont mis en file ; les autres
 * campagnes ne sont pas impactées.
 */
export async function withCampaignLock<T>(campaignId: string, fn: () => Promise<T>): Promise<T> {
  const previous = locks.get(campaignId) ?? Promise.resolve()

  let release!: () => void
  const gate = new Promise<void>((resolve) => {
    release = resolve
  })

  // La fin de notre verrou ne se résout que lorsque fn sera terminée (release).
  const current: Promise<unknown> = previous.then(() => gate)
  locks.set(campaignId, current)

  try {
    // On attend son tour (la chaîne ne rejette jamais : gate n'est résolue que via release).
    await previous
    return await fn()
  } finally {
    release()
    // Si personne n'a enchaîné derrière nous, on nettoie l'entrée de la Map.
    if (locks.get(campaignId) === current) {
      locks.delete(campaignId)
    }
  }
}
