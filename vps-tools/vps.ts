/**
 * Minimal VPS CLI over ssh2 (password auth).
 * Usage:
 *   bun run vps.ts exec "<command>"            -> run command, stream output
 *   bun run vps.ts put <local> <remote>        -> upload file (SFTP)
 *   bun run vps.ts putdir <localDir> <remoteDir> -> upload directory recursively
 *   bun run vps.ts get <remote> <local>        -> download file
 */
import { readFileSync, statSync, readdirSync, createReadStream, createWriteStream, mkdirSync } from "node:fs";
import { join, basename, relative } from "node:path";
import { Client, type ClientCallback, type ConnectConfig, type ExecOptions, SFTPWrapper } from "ssh2";

const HOST = process.env.VPS_HOST || "95.111.226.63";
const PORT = Number(process.env.VPS_PORT || 22);
const USER = process.env.VPS_USER || "aenews";
const PASS = process.env.VPS_PASS || "REDACTED";

const cfg: ConnectConfig = {
  host: HOST,
  port: PORT,
  username: USER,
  password: PASS,
  readyTimeout: 25000,
  keepaliveInterval: 10000,
};

function connect(): Promise<Client> {
  return new Promise((resolve, reject) => {
    const conn = new Client();
    conn.on("ready", () => resolve(conn));
    conn.on("error", reject);
    conn.connect(cfg);
  });
}

function exec(conn: Client, cmd: string, timeoutMs = 600000): Promise<{ code: number; out: string }> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`exec timeout after ${timeoutMs}ms: ${cmd.slice(0, 120)}`)), timeoutMs);
    conn.exec(cmd, (err, stream) => {
      if (err) { clearTimeout(timer); return reject(err); }
      let out = "";
      stream.on("data", (d: Buffer) => { out += d.toString(); process.stdout.write(d); });
      stream.stderr.on("data", (d: Buffer) => { out += d.toString(); process.stderr.write(d); });
      stream.on("close", (code: number | null) => { clearTimeout(timer); resolve({ code: code ?? -1, out }); });
    });
  });
}

function sftp(conn: Client): Promise<SFTPWrapper> {
  return new Promise((resolve, reject) => {
    conn.sftp((err, s) => (err ? reject(err) : resolve(s)));
  });
}

function sftpMkdirp(sftpC: SFTPWrapper, remoteDir: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const parts = remoteDir.split("/").filter(Boolean);
    let cur = remoteDir.startsWith("/") ? "/" : "";
    const next = (i: number): void => {
      if (i >= parts.length) return resolve();
      cur = cur === "/" ? `/${parts[i]}` : `${cur}/${parts[i]}`;
      sftpC.mkdir(cur, (e) => {
        // ignore "already exists" failures, verify by stat
        sftpC.exists(cur, (ok) => {
          if (!ok) return reject(e ?? new Error(`mkdir failed: ${cur}`));
          next(i + 1);
        });
      });
    };
    next(0);
  });
}

function sftpPut(sftpC: SFTPWrapper, local: string, remote: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const rs = createReadStream(local);
    const ws = sftpC.createWriteStream(remote);
    rs.pipe(ws);
    ws.on("error", reject);
    ws.on("close", () => resolve());
  });
}

async function putdir(conn: Client, localDir: string, remoteDir: string): Promise<void> {
  const sftpC = await sftp(conn);
  await sftpMkdirp(sftpC, remoteDir);
  const walk = async (ld: string, rd: string): Promise<void> => {
    for (const entry of readdirSync(ld, { withFileTypes: true })) {
      const lp = join(ld, entry.name);
      const rp = `${rd}/${entry.name}`;
      if (entry.isDirectory()) {
        await sftpMkdirp(sftpC, rp);
        await walk(lp, rp);
      } else if (entry.isFile()) {
        process.stdout.write(`  ↑ ${relative(localDir, lp)}\n`);
        await sftpPut(sftpC, lp, rp);
      }
    }
  };
  await walk(localDir, remoteDir);
  sftpC.end();
}

async function main(): Promise<void> {
  const [, , action, ...rest] = process.argv;
  const conn = await connect();
  try {
    if (action === "exec") {
      const cmd = rest.join(" ");
      const { code } = await exec(conn, cmd);
      process.exitCode = code === 0 ? 0 : 1;
    } else if (action === "put") {
      const sftpC = await sftp(conn);
      const remote = rest[1];
      await sftpMkdirp(sftpC, remote.split("/").slice(0, -1).join("/") || "/");
      await sftpPut(sftpC, rest[0], remote);
      console.log(`uploaded ${rest[0]} -> ${remote}`);
      sftpC.end();
    } else if (action === "putdir") {
      await putdir(conn, rest[0], rest[1]);
      console.log(`dir uploaded ${rest[0]} -> ${rest[1]}`);
    } else if (action === "get") {
      const sftpC = await sftp(conn);
      await new Promise<void>((resolve, reject) => {
        sftpC.fastGet(rest[0], rest[1], (e) => (e ? reject(e) : resolve()));
      });
      console.log(`downloaded ${rest[0]} -> ${rest[1]}`);
      sftpC.end();
    } else {
      console.error("unknown action; use exec|put|putdir|get");
      process.exitCode = 2;
    }
  } finally {
    conn.end();
  }
}

main().catch((e) => {
  console.error(`VPS-CLI-ERROR: ${e instanceof Error ? e.message : String(e)}`);
  process.exit(1);
});
