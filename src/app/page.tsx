import { AuthError } from "next-auth";
import { redirect } from "next/navigation";
import { auth, signIn, signOut } from "@/auth";
import { SPID_LEVELS, type SpidLevel } from "@/lib/oidc";

export const dynamic = "force-dynamic";

async function login(level: SpidLevel) {
  "use server";
  try {
    await signIn(`spid-${level.toLowerCase()}`, { redirectTo: "/" });
  } catch (error) {
    if (error instanceof AuthError) {
      console.error("[auth] Unable to start OIDC login", error);
      redirect("/?error=LoginFailed");
    }
    throw error;
  }
}

export default async function Home({
  searchParams,
}: {
  searchParams: Promise<{ error?: string }>;
}) {
  const [session, params] = await Promise.all([auth(), searchParams]);
  const errorMessage = params.error === "InsufficientAcr"
    ? "Il livello restituito dall'IdP non soddisfa quello richiesto. La sessione precedente non e' stata revocata."
    : "Login non completato. La sessione precedente non e' stata revocata. Consulta i log del server per i dettagli.";

  return (
    <main>
      <header>
        <p className="eyebrow">NEXT.JS + AUTH.JS</p>
        <h1>SPID OIDC Playground</h1>
        <p>Una nuova login per ogni livello. Nessuna revoca durante lo step-up.</p>
      </header>

      {params.error && <p className="error" role="alert">{errorMessage}</p>}

      <section aria-labelledby="session-title">
        <h2 id="session-title">Sessione</h2>
        <p role="status">
          {session ? `Utente autenticato - SPID ${session.level}` : "Utente non autenticato"}
        </p>
        {session ? (
          <>
            <p>Scadenza assoluta: <time dateTime={session.expires}>{session.expires}</time></p>
            <pre aria-label="Dettagli della sessione">{JSON.stringify(session, null, 2)}</pre>
            <form action={async () => {
              "use server";
              await signOut({ redirectTo: "/" });
            }}>
              <button className="secondary" type="submit">Logout locale</button>
            </form>
          </>
        ) : <p>Effettua il login per visualizzare i dettagli della sessione.</p>}
      </section>

      <section aria-labelledby="login-title">
        <h2 id="login-title">Login</h2>
        <div className="actions">
          {SPID_LEVELS.map((level) => (
            <form key={level} action={login.bind(null, level)}>
              <button type="submit">Login con SPID {level}</button>
            </form>
          ))}
        </div>
        <p className="note">
          Ogni login richiede almeno il livello scelto tramite acr_values.
          Una login riuscita sostituisce il cookie corrente con un nuovo JWE valido
          per un&apos;ora. La sessione precedente resta valida fino alla propria scadenza.
        </p>
      </section>
    </main>
  );
}
