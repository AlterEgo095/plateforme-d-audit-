import type { Metadata } from "next";
import Link from "next/link";
import { ArrowLeft, Shield } from "lucide-react";

export const metadata: Metadata = {
  title: "Mentions légales & Politique de confidentialité — AuditForge",
  description:
    "Mentions légales et politique de confidentialité (RGPD) de la plateforme AuditForge.",
  robots: { index: true, follow: true },
};

// ─── Informations éditables (à adapter au titulaire réel de la plateforme) ──
const OPERATOR = "AENEWS";
const SERVICE_NAME = "AuditForge";
const CONTACT_EMAIL = "contact@aenews.online";
const PUBLICATION_DATE = "1er novembre 2026";

function Section({
  id,
  title,
  children,
}: {
  id: string;
  title: string;
  children: React.ReactNode;
}) {
  return (
    <section aria-labelledby={id} className="space-y-3">
      <h2 id={id} className="text-foreground text-xl font-semibold tracking-tight">
        {title}
      </h2>
      {children}
    </section>
  );
}

function P({ children }: { children: React.ReactNode }) {
  return <p className="text-muted-foreground leading-relaxed">{children}</p>;
}

export default function LegalPage() {
  return (
    <main className="min-h-screen">
      <div className="mx-auto w-full max-w-3xl space-y-10 px-4 py-10 sm:px-6">
        <header className="space-y-4">
          <Link
            href="/"
            className="text-muted-foreground hover:text-foreground inline-flex min-h-11 items-center gap-1.5 text-sm transition-colors sm:min-h-0"
          >
            <ArrowLeft className="size-4" aria-hidden />
            Retour à la plateforme
          </Link>
          <div className="flex items-center gap-3">
            <div
              className="border-primary/50 bg-primary/10 text-primary flex size-11 shrink-0 items-center justify-center rounded-full border-2"
              aria-hidden
            >
              <Shield className="size-5" />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-tight">
                Mentions légales &amp; confidentialité
              </h1>
              <p className="text-muted-foreground text-sm">
                {SERVICE_NAME} — plateforme d&apos;audit de sécurité auto-hébergée
              </p>
            </div>
          </div>
          <p className="text-muted-foreground text-xs">
            Dernière mise à jour : {PUBLICATION_DATE}
          </p>
        </header>

        {/* ── Mentions légales ─────────────────────────────────────────────── */}
        <div className="space-y-8">
          <h2 className="text-foreground border-b pb-2 text-lg font-semibold uppercase tracking-wide">
            Mentions légales
          </h2>

          <Section id="editeur" title="Éditeur de la plateforme">
            <P>
              La plateforme {SERVICE_NAME} est exploitée par {OPERATOR}
              (&laquo;&nbsp;l&apos;éditeur&nbsp;&raquo;). Pour toute question relative à
              cette plateforme ou à vos données&nbsp;:{" "}
              <a
                href={`mailto:${CONTACT_EMAIL}`}
                className="text-foreground underline underline-offset-4"
              >
                {CONTACT_EMAIL}
              </a>
              .
            </P>
            <P>
              Directeur de la publication&nbsp;: le représentant légal de {OPERATOR}.
            </P>
          </Section>

          <Section id="hebergement" title="Hébergement">
            <P>
              La plateforme est auto-hébergée sur un serveur privé virtuel (VPS),
              distribué derrière le réseau de diffusion de contenu (CDN) Cloudflare,
              Inc. Les communications avec la plateforme sont chiffrées (HTTPS/TLS).
            </P>
          </Section>

          <Section id="finalite" title="Finalité du service">
            <P>
              {SERVICE_NAME} est un outil professionnel d&apos;audit et de test
              d&apos;intrusion destiné aux opérateurs autorisés. Il permet
              d&apos;orchestrer des campagnes de scan de sécurité contre des cibles
              dont l&apos;utilisateur déclare détenir l&apos;autorisation expresse du
              propriétaire. Toute utilisation contre des systèmes sans autorisation
              préalable est strictement interdite.
            </P>
          </Section>
        </div>

        {/* ── Politique de confidentialité ────────────────────────────────── */}
        <div className="space-y-8 border-t pt-8">
          <h2 className="text-foreground border-b pb-2 text-lg font-semibold uppercase tracking-wide">
            Politique de confidentialité (RGPD)
          </h2>

          <Section id="responsable" title="Responsable du traitement">
            <P>
              Le responsable du traitement des données personnelles traitées par la
              plateforme est {OPERATOR}, joignable à l&apos;adresse{" "}
              <a
                href={`mailto:${CONTACT_EMAIL}`}
                className="text-foreground underline underline-offset-4"
              >
                {CONTACT_EMAIL}
              </a>
              .
            </P>
          </Section>

          <Section id="donnees" title="Données collectées">
            <ul className="text-muted-foreground list-disc space-y-2 pl-5 leading-relaxed">
              <li>
                <span className="text-foreground font-medium">Comptes opérateurs</span>&nbsp;:
                identifiant, hachage du mot de passe (scrypt), rôle, date de création.
                Aucun mot de passe n&apos;est stocké en clair.
              </li>
              <li>
                <span className="text-foreground font-medium">Journal d&apos;audit</span>&nbsp;:
                horodatage, auteur, action réalisée (connexion, lancement de scan,
                qualification de constat…) — registre technique de traçabilité.
              </li>
              <li>
                <span className="text-foreground font-medium">Contenus de travail</span>&nbsp;:
                campagnes, cibles de scan que vous saisissez, résultats et constats
                produits par les outils d&apos;audit.
              </li>
              <li>
                <span className="text-foreground font-medium">Données techniques</span>&nbsp;:
                adresse IP et en-têtes de requête, traités à des fins de sécurité
                (limitation de débit, prévention des abus).
              </li>
            </ul>
          </Section>

          <Section id="bases" title="Finalités et bases légales">
            <ul className="text-muted-foreground list-disc space-y-2 pl-5 leading-relaxed">
              <li>
                Fournir le service d&apos;audit aux utilisateurs autorisés — exécution
                du contrat (art. 6.1.b RGPD).
              </li>
              <li>
                Sécuriser la plateforme (authentification, traçabilité, limitation de
                débit) — intérêt légitime (art. 6.1.f RGPD).
              </li>
              <li>
                Répondre aux obligations légales applicables — obligation légale
                (art. 6.1.c RGPD).
              </li>
            </ul>
          </Section>

          <Section id="duree" title="Durée de conservation">
            <P>
              Les comptes sont conservés tant que l&apos;utilisateur est actif, puis
              supprimés sur demande. Les journaux de scan sont purgés au-delà de la
              période de rétention configurée (30 jours par défaut)&nbsp;; le journal
              d&apos;audit et les constats qualifiés sont conservés pour la durée de
              vie de la plateforme à des fins de traçabilité professionnelle. Les
              sessions expirent automatiquement après 8 heures.
            </P>
          </Section>

          <Section id="cookies" title="Cookies">
            <P>
              La plateforme n&apos;utilise aucun cookie publicitaire ni traceur
              tiers. Deux cookies techniques sont posés&nbsp;:
            </P>
            <ul className="text-muted-foreground list-disc space-y-2 pl-5 leading-relaxed">
              <li>
                <code className="text-foreground bg-muted rounded px-1.5 py-0.5 text-xs">
                  af_session
                </code>{" "}
                — cookie de session <em>strictement nécessaire</em>, HttpOnly, SameSite=Lax,
                Secure en HTTPS, expirant après 8 heures&nbsp;;
              </li>
              <li>
                <code className="text-foreground bg-muted rounded px-1.5 py-0.5 text-xs">
                  NEXT_LOCALE
                </code>{" "}
                — préférence de langue, non sensible.
              </li>
            </ul>
          </Section>

          <Section id="destinataires" title="Destinataires et sous-traitants">
            <P>
              Les données restent auto-hébergées et ne sont ni vendues, ni cédées, ni
              utilisées à des fins publicitaires. Les sous-traitants techniques
              limités au strict nécessaire sont l&apos;hébergeur du VPS et le CDN
              Cloudflare (transit chiffré). Aucun transfert de données n&apos;est
              initié par la plateforme vers des tiers, hors configuration explicite
              de l&apos;administrateur (ex.&nbsp;: export optionnel vers une instance
              DefectDojo choisie par lui).
            </P>
          </Section>

          <Section id="securite" title="Sécurité">
            <P>
              Mots de passe hachés avec scrypt et sel aléatoire, sessions signées
              HMAC-SHA256 comparées à temps constant, contrôle d&apos;accès par rôles
              (RBAC), en-têtes de sécurité HTTP (CSP, HSTS, anti-clickjacking),
              limitation de débit sur l&apos;authentification, journalisation des
              actions sensibles et chiffrement TLS de bout en bout.
            </P>
          </Section>

          <Section id="droits" title="Vos droits">
            <P>
              Conformément au RGPD, vous disposez d&apos;un droit d&apos;accès, de
              rectification, d&apos;effacement, de limitation, d&apos;opposition et de
              portabilité de vos données, ainsi que du droit d&apos;introduire une
              réclamation auprès de la CNIL (cnil.fr). Pour exercer vos droits,
              écrivez à{" "}
              <a
                href={`mailto:${CONTACT_EMAIL}`}
                className="text-foreground underline underline-offset-4"
              >
                {CONTACT_EMAIL}
              </a>{" "}
              — une réponse vous sera apportée dans un délai maximal d&apos;un mois.
            </P>
          </Section>
        </div>

        <footer className="text-muted-foreground border-t pt-6 text-xs">
          <p>
            {SERVICE_NAME} v1.0 — Plateforme d&apos;audit unifiée auto-hébergée.
            Usage réservé aux audits autorisés.
          </p>
        </footer>
      </div>
    </main>
  );
}
