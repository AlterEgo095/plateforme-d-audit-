/**
 * AuditForge — Client Prisma du moteur (singleton).
 *
 * Stocké sur globalThis pour survivre aux rechargements `bun --hot`
 * (sinon, plusieurs pools de connexions SQLite coexisteraient).
 */

import { PrismaClient } from "@prisma/client";

const globalForPrisma = globalThis as unknown as {
  __auditforgeScanEnginePrisma?: PrismaClient;
};

export const db: PrismaClient =
  globalForPrisma.__auditforgeScanEnginePrisma ??
  new PrismaClient({
    log: ["error", "warn"],
  });

globalForPrisma.__auditforgeScanEnginePrisma = db;
