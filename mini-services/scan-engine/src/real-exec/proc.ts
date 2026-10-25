/**
 * AuditForge — Utilitaires subprocess pour les adaptateurs réels.
 *
 * - which(bin) : résolution d'un binaire dans le PATH ;
 * - runStreaming : exécute une commande, diffuse chaque ligne (stdout+stderr)
 *   via le callback, résout avec le code de sortie ; annulable via signal ;
 * - killTree : tue le processus et ses enfants (groups de processus POSIX).
 */

import { spawn, type ChildProcess } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

/** Résout un binaire dans le PATH — retourne null si introuvable. */
export function which(bin: string): string | null {
  if (bin.includes("/")) {
    return existsSync(bin) ? bin : null; // chemin explicite
  }
  const paths = (process.env.PATH ?? "").split(":").filter(Boolean);
  for (const dir of paths) {
    if (existsSync(join(dir, bin))) return join(dir, bin);
  }
  return null;
}

/** Version courte d'un binaire (première ligne de sa sortie d'info), null si indisponible. */
export async function probeVersion(
  bin: string,
  timeoutMs = 8000,
  args: string[] = ["--version"],
): Promise<string | null> {
  const resolved = which(bin);
  if (!resolved) return null;
  return new Promise((resolve) => {
    let child: ChildProcess;
    try {
      child = spawn(resolved, args, { stdio: ["ignore", "pipe", "pipe"] });
    } catch {
      resolve(null);
      return;
    }
    let out = "";
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      resolve(null);
    }, timeoutMs);
    child.stdout?.on("data", (d: Buffer) => {
      out += d.toString("utf8");
    });
    child.on("error", () => {
      clearTimeout(timer);
      resolve(null);
    });
    child.on("close", () => {
      clearTimeout(timer);
      // Première ligne NON VIDE (rich/Typer pad la sortie d'un retour à la ligne initial).
      const firstLine = out
        .split("\n")
        .map((l) => l.trim())
        .find((l) => l.length > 0);
      resolve(firstLine ?? null);
    });
  });
}

export interface RunStreamingOptions {
  cmd: string;
  args: string[];
  cwd?: string;
  env?: Record<string, string>;
  timeoutMs?: number;
  signal?: AbortSignal;
  /** Appelé pour chaque ligne émise (stdout et stderr). */
  onLine: (line: string, isErr: boolean) => void | Promise<void>;
}

export interface RunStreamingResult {
  exitCode: number | null;
  signal: NodeJS.Signals | null;
  timedOut: boolean;
  aborted: boolean;
}

const MAX_LINE_LENGTH = 2000;

/**
 * m7 (audit 8-a) : environnement MINIMAL transmis aux CLI d'audit. Le processus
 * moteur porte des secrets (AUTH_SECRET, ENGINE_INTERNAL_TOKEN, clés LLM) qui
 * ne doivent PAS fuiter vers les outils — ni vers leurs conteneurs Docker.
 * Allowlist système + variables outils ajoutées explicitement par les
 * adaptateurs (paramètre `env` de RunStreamingOptions).
 */
const ALLOWED_ENV_KEYS = [
  "PATH",
  "HOME",
  "TMPDIR",
  "LANG",
  "LC_ALL",
  "TZ",
  "TERM",
  "DOCKER_HOST",
  "HTTP_PROXY",
  "HTTPS_PROXY",
  "NO_PROXY",
] as const;

function sanitizedEnv(extra?: Record<string, string>): NodeJS.ProcessEnv {
  // PYTHONUNBUFFERED : garantit des logs Python (Typer/rich) diffusés en temps réel.
  // NODE_ENV : requis par les types Bun (ProcessEnv) — valeur bénigne pour les outils.
  const env: NodeJS.ProcessEnv = {
    PYTHONUNBUFFERED: "1",
    NODE_ENV: process.env.NODE_ENV ?? "development",
  };
  for (const key of ALLOWED_ENV_KEYS) {
    const value = process.env[key];
    if (value !== undefined) env[key] = value;
  }
  return extra ? { ...env, ...extra } : env;
}

/** Découpe un buffer en lignes complètes ; retourne le reste. */
class LineBuffer {
  private buf = "";
  push(chunk: string, onLine: (line: string) => void | Promise<void>): Promise<void> {
    this.buf += chunk;
    const parts = this.buf.split("\n");
    this.buf = parts.pop() ?? "";
    return (async () => {
      for (const raw of parts) {
        const line = raw.replace(/\r$/, "");
        await onLine(line.length > MAX_LINE_LENGTH ? line.slice(0, MAX_LINE_LENGTH) + "…" : line);
      }
    })();
  }
  async flush(onLine: (line: string) => void | Promise<void>): Promise<void> {
    const rest = this.buf.replace(/\r$/, "");
    this.buf = "";
    if (rest.trim()) await onLine(rest.slice(0, MAX_LINE_LENGTH));
  }
}

/** Exécute une commande en diffusant ses lignes ; kill du groupe sur abort/timeout. */
export async function runStreaming(opts: RunStreamingOptions): Promise<RunStreamingResult> {
  const resolved = which(opts.cmd);
  if (!resolved) throw new Error(`binaire introuvable dans le PATH : ${opts.cmd}`);

  return new Promise<RunStreamingResult>((resolve, reject) => {
    let settled = false;
    let timedOut = false;
    let aborted = false;

    // Annotation explicite : l'intersection des surcharges de spawn avec
    // stdio mixte se réduit à `never` sous tsc strict (sinon .stdout devient
    // inaccessible). ChildProcess suffit — le code utilise `?.` partout.
    const child: ChildProcess = spawn(resolved, opts.args, {
      cwd: opts.cwd,
      env: sanitizedEnv(opts.env),
      stdio: ["ignore", "pipe", "pipe"],
      detached: true, // groupe de processus → kill arborescent
    });

    const killTree = (sig: NodeJS.Signals = "SIGTERM"): void => {
      try {
        if (child.pid) process.kill(-child.pid, sig);
      } catch {
        try {
          child.kill(sig);
        } catch {
          /* déjà terminé */
        }
      }
    };

    const onAbort = (): void => {
      aborted = true;
      killTree("SIGTERM");
      setTimeout(() => {
        if (!settled) killTree("SIGKILL");
      }, 3000).unref();
    };
    if (opts.signal) {
      if (opts.signal.aborted) onAbort();
      else opts.signal.addEventListener("abort", onAbort, { once: true });
    }

    const timer =
      opts.timeoutMs && opts.timeoutMs > 0
        ? setTimeout(() => {
            timedOut = true;
            killTree("SIGTERM");
            setTimeout(() => {
              if (!settled) killTree("SIGKILL");
            }, 3000).unref();
          }, opts.timeoutMs)
        : null;

    const stdoutBuf = new LineBuffer();
    const stderrBuf = new LineBuffer();

    const outDone = (async () => {
      child.stdout?.setEncoding("utf8");
      child.stdout?.on("data", (chunk: string) => {
        void stdoutBuf.push(chunk, (line) => opts.onLine(line, false));
      });
      child.stderr?.setEncoding("utf8");
      child.stderr?.on("data", (chunk: string) => {
        void stderrBuf.push(chunk, (line) => opts.onLine(line, true));
      });
    })();

    child.on("error", (err) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      reject(err);
    });

    child.on("close", (code, sig) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      void (async () => {
        await Promise.all([
          stdoutBuf.flush((line) => opts.onLine(line, false)),
          stderrBuf.flush((line) => opts.onLine(line, true)),
          outDone.catch(() => undefined),
        ]);
        resolve({ exitCode: code, signal: sig, timedOut, aborted });
      })();
    });
  });
}

/** Crée un répertoire de travail temporaire unique. */
export async function makeWorkdir(prefix: string): Promise<string> {
  return mkdtemp(join(tmpdir(), `auditforge-${prefix}-`));
}

/** Supprime récursivement un répertoire (best effort, contenu protégé). */
export async function removeWorkdir(dir: string | null): Promise<void> {
  if (!dir) return;
  try {
    await rm(dir, { recursive: true, force: true });
  } catch (err) {
    console.warn("[real-exec] nettoyage du répertoire de travail impossible:", dir, err);
  }
}
