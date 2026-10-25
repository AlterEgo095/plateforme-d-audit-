"use client";

/**
 * AuditForge — Écran de connexion (identifiant / mot de passe / TOTP MFA).
 */

import { useState } from "react";
import {
  AlertCircle,
  Eye,
  EyeOff,
  Loader2,
  Shield,
  ShieldCheck,
  User,
  KeyRound,
} from "lucide-react";
import {
  InputOTP,
  InputOTPGroup,
  InputOTPSlot,
} from "@/components/ui/input-otp";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { apiPost, ApiError, getErrorMessage } from "@/lib/api-client";
import type { UserDTO } from "@/lib/types";

const DEMO_ACCOUNTS = [
  { username: "admin", password: "Admin123!", role: "Administrateur" },
  { username: "auditeur", password: "Audit123!", role: "Auditeur" },
  { username: "observateur", password: "View123!", role: "Observateur" },
];

export function LoginScreen({ onLogin }: { onLogin: (user: UserDTO) => void }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [mfaRequired, setMfaRequired] = useState(false);
  const [totp, setTotp] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const submit = async (e?: React.FormEvent) => {
    e?.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const body: Record<string, string> = { username, password };
      if (mfaRequired && totp) body.totp = totp;
      const res = await apiPost<{ user: UserDTO }>("/api/auth/login", body);
      onLogin(res.user);
    } catch (err) {
      if (err instanceof ApiError && err.status === 428) {
        setMfaRequired(true);
      } else {
        const msg = getErrorMessage(err);
        setError(msg);
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <main
      className="relative flex min-h-screen items-center justify-center overflow-hidden p-4"
      style={{
        background:
          "radial-gradient(ellipse 80% 60% at 50% 0%, oklch(0.696 0.17 162.48 / 0.12), transparent 70%)",
      }}
      aria-label="Page de connexion AuditForge"
    >
      <h1 className="sr-only">Connexion — AuditForge</h1>
      <div className="terminal-grid pointer-events-none absolute inset-0" aria-hidden />

      <Card className="relative w-full max-w-sm shadow-xl">
        <CardHeader className="items-center space-y-3 text-center">
          <div
            className="border-primary/50 bg-primary/10 text-primary mx-auto flex size-14 items-center justify-center rounded-full border-2"
            aria-hidden
          >
            <Shield className="size-7" />
          </div>
          <div className="space-y-1">
            <CardTitle className="text-2xl font-bold tracking-tight">
              AuditForge
            </CardTitle>
            <CardDescription>
              Plateforme d&apos;audit unifiée — accès opérateur
            </CardDescription>
          </div>
        </CardHeader>

        <CardContent className="space-y-4">
          {error && (
            <Alert variant="destructive" role="alert">
              <AlertCircle className="size-4" />
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}

          {!mfaRequired ? (
            <form onSubmit={submit} className="space-y-4" aria-label="Formulaire de connexion">
              <div className="space-y-2">
                <Label htmlFor="username">Identifiant</Label>
                <div className="relative">
                  <User className="text-muted-foreground pointer-events-none absolute top-2.5 left-3 size-4" aria-hidden />
                  <Input
                    id="username"
                    className="pl-9"
                    autoComplete="username"
                    placeholder="ex. auditeur"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    required
                  />
                </div>
              </div>

              <div className="space-y-2">
                <Label htmlFor="password">Mot de passe</Label>
                <div className="relative">
                  <KeyRound className="text-muted-foreground pointer-events-none absolute top-2.5 left-3 size-4" aria-hidden />
                  <Input
                    id="password"
                    type={showPassword ? "text" : "password"}
                    className="pr-10 pl-9"
                    autoComplete="current-password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                  />
                  <button
                    type="button"
                    aria-label={showPassword ? "Masquer le mot de passe" : "Afficher le mot de passe"}
                    className="text-muted-foreground hover:text-foreground absolute top-1/2 right-0.5 flex size-11 -translate-y-1/2 items-center justify-center rounded-md"
                    onClick={() => setShowPassword((v) => !v)}
                  >
                    {showPassword ? <EyeOff className="size-4" /> : <Eye className="size-4" />}
                  </button>
                </div>
              </div>

              <Button type="submit" className="h-11 w-full" disabled={loading}>
                {loading && <Loader2 className="size-4 animate-spin" aria-hidden />}
                {loading ? "Connexion…" : "Se connecter"}
              </Button>
            </form>
          ) : (
            <form onSubmit={submit} className="space-y-4" aria-label="Vérification en deux étapes">
              <div className="text-center">
                <div
                  className="mx-auto mb-3 flex size-10 items-center justify-center rounded-full"
                  style={{ backgroundColor: "#10b9811a", color: "#34d399" }}
                  aria-hidden
                >
                  <ShieldCheck className="size-5" />
                </div>
                <p className="text-sm font-semibold">Authentification à deux facteurs</p>
                <p className="text-muted-foreground text-sm">
                  Saisissez le code à 6 chiffres de votre application TOTP.
                </p>
              </div>

              <div className="flex justify-center">
                <InputOTP
                  maxLength={6}
                  value={totp}
                  onChange={setTotp}
                  autoFocus
                  aria-label="Code TOTP à 6 chiffres"
                >
                  <InputOTPGroup>
                    {[0, 1, 2, 3, 4, 5].map((i) => (
                      <InputOTPSlot key={i} index={i} className="size-11" />
                    ))}
                  </InputOTPGroup>
                </InputOTP>
              </div>

              <p className="text-muted-foreground text-center text-xs">
                Code TOTP de démonstration : <span className="text-foreground font-mono font-semibold">123456</span>
              </p>

              <Button
                type="submit"
                className="h-11 w-full"
                disabled={loading || totp.length !== 6}
              >
                {loading && <Loader2 className="size-4 animate-spin" aria-hidden />}
                {loading ? "Vérification…" : "Valider"}
              </Button>
            </form>
          )}

          <Separator />

          <div className="space-y-2">
            <p className="text-muted-foreground text-center text-xs font-medium uppercase tracking-wide">
              Comptes de démonstration
            </p>
            <div
              className="flex flex-wrap justify-center gap-2"
              role="group"
              aria-label="Comptes de démonstration"
            >
              {DEMO_ACCOUNTS.map((acc) => (
                <button
                  key={acc.username}
                  type="button"
                  className="hover:bg-accent hover:text-accent-foreground inline-flex min-h-11 sm:min-h-9 items-center gap-1.5 rounded-full border px-3 py-1.5 text-xs transition-colors"
                  aria-label={`Remplir les identifiants du compte ${acc.role}`}
                  onClick={() => {
                    setUsername(acc.username);
                    setPassword(acc.password);
                    setMfaRequired(false);
                    setTotp("");
                    setError(null);
                  }}
                >
                  <span className="font-semibold">{acc.username}</span>
                  <span className="text-muted-foreground">· {acc.role}</span>
                </button>
              ))}
            </div>
          </div>
        </CardContent>
      </Card>
    </main>
  );
}
