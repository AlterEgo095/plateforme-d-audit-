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

export async function prepareTarget(ctx: RealAdapterContext): Promise<PreparedTarget> {
  if (ctx.targetType !== "GIT") {
    return { value: ctx.target, cloned: false };
  }
  const dest = join(ctx.workdir, "target-repo");
  await ctx.onLog(`git clone --depth 1 ${ctx.target} → ${dest}`, "CMD", "git");
  const result = await runStreaming({
    cmd: "git",
    args: ["clone", "--depth", "1", "--single-branch", ctx.target, dest],
    signal: ctx.signal,
    timeoutMs: 5 * 60_000,
    onLine: (line, isErr) => ctx.onLog(line, isErr ? "WARN" : "INFO", "git"),
  });
  if (result.exitCode !== 0) {
    throw new Error(`Clonage Git impossible (code ${result.exitCode}) : ${ctx.target}`);
  }
  return { value: dest, cloned: true };
}
