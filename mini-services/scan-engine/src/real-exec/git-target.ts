/**
 * AuditForge — Préparation des cibles pour les outils réels.
 *
 * Les cibles GIT sont clonées (superficielle) dans le répertoire de travail
 * du scan : Basalt audite un répertoire de code, Phantom accepte aussi un
 * dossier projet. Les cibles URL sont transmises telles quelles.
 */

import { join } from "node:path";
import { runStreaming } from "./proc";
import type { RealAdapterContext } from "./types";

export interface PreparedTarget {
  /** Chemin local (répertoire) ou URL à passer à l'outil. */
  value: string;
  /** true si la cible a été clonée dans workdir (nettoyage géré par le moteur). */
  cloned: boolean;
}

// C1 (audit 8-a) — défense en profondeur : la validation applicative (Next.js)
// peut être contournée par un appel direct au moteur ; on réimpose donc ICI le
// schéma de la cible GIT. Sans cela, une cible `ext::sh -c …` ou débutant par
// `--upload-pack=…` serait passée telle quelle à `git clone` → exécution de
// commande arbitraire sur le conteneur moteur (qui monte docker.sock).
const GIT_TARGET_RE = /^(https?:\/\/|ssh:\/\/|git@)[^\s]+$/i;

export function assertSafeGitTarget(target: string): void {
  if (target.startsWith("-") || !GIT_TARGET_RE.test(target)) {
    throw new Error(
      "Cible GIT refusée (formats acceptés : https://…, ssh://…, git@hôte:chemin — aucune option ni transport alternatif)",
    );
  }
}

export async function prepareTarget(ctx: RealAdapterContext): Promise<PreparedTarget> {
  if (ctx.targetType !== "GIT") {
    return { value: ctx.target, cloned: false };
  }
  assertSafeGitTarget(ctx.target);
  const dest = join(ctx.workdir, "target-repo");
  await ctx.onLog(`git clone --depth 1 ${ctx.target} → ${dest}`, "CMD", "git");
  let stderrTail = "";
  const result = await runStreaming({
    cmd: "git",
    args: ["clone", "--depth", "1", "--single-branch", ctx.target, dest],
    signal: ctx.signal,
    timeoutMs: 5 * 60_000,
    onLine: (line, isErr) => {
      if (isErr) stderrTail = `${stderrTail}\n${line}`.slice(-600);
      ctx.onLog(line, isErr ? "WARN" : "INFO", "git");
    },
  });
  if (result.exitCode !== 0) {
    // Repli légitime : les dépôts servis en transport HTTP « dumb » (fichiers
    // statiques + update-server-info — ex. serveurs de fixtures) ne supportent
    // PAS le clonage superficiel (« dumb http transport does not support
    // shallow capabilities »). On retente SANS --depth : dépôt plus ancien
    // mais fidèle. Toute autre erreur reste rédhibitoire.
    if (/dumb http transport does not support shallow/i.test(stderrTail)) {
      await ctx.onLog("repli : transport HTTP dumb détecté — clone complet (sans --depth 1)", "INFO", "git");
      const retry = await runStreaming({
        cmd: "git",
        args: ["clone", "--single-branch", ctx.target, dest],
        signal: ctx.signal,
        timeoutMs: 5 * 60_000,
        onLine: (line, isErr) => ctx.onLog(line, isErr ? "WARN" : "INFO", "git"),
      });
      if (retry.exitCode !== 0) {
        throw new Error(`Clonage Git impossible (code ${retry.exitCode}) : ${ctx.target}`);
      }
      return { value: dest, cloned: true };
    }
    throw new Error(`Clonage Git impossible (code ${result.exitCode}) : ${ctx.target}`);
  }
  return { value: dest, cloned: true };
}
