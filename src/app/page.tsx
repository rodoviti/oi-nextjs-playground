"use client";

import { useEffect, useRef, useState } from "react";
import { loginErrorMessage, SPID_LEVELS, type SpidLevel } from "@/lib/oidc";
import type { AppSession } from "@/lib/session";

async function jsonResponse(response: Response) {
  const data = await response.json();
  if (!response.ok) throw new Error(data.error ?? "Richiesta non completata");
  return data;
}

function base64url(bytes: Uint8Array) {
  return btoa(String.fromCharCode(...bytes)).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

export default function Home() {
  const [token, setToken] = useState<string | null>(null);
  const [session, setSession] = useState<AppSession | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const cancelLogin = useRef<(() => void) | null>(null);

  useEffect(() => () => cancelLogin.current?.(), []);

  useEffect(() => {
    if (!session) return;
    const timer = setTimeout(() => {
      setToken(null);
      setSession(null);
      setError("Sessione scaduta. Effettua una nuova login.");
    }, Math.max(0, Date.parse(session.expires) - Date.now()));
    return () => clearTimeout(timer);
  }, [session]);

  async function login(level: SpidLevel) {
    const popup = window.open("about:blank", "spid-login", "popup,width=600,height=750");
    if (!popup) {
      setError("Abilita le finestre popup per completare il login.");
      return;
    }
    setBusy(true);
    setError("");
    const requestId = base64url(crypto.getRandomValues(new Uint8Array(32)));
    let processing = false;

    function cleanup() {
      window.removeEventListener("message", onMessage);
      clearInterval(timer);
      clearTimeout(timeout);
      popup?.close();
      cancelLogin.current = null;
      setBusy(false);
    }

    async function onMessage(event: MessageEvent) {
      if (event.origin !== window.location.origin || event.source !== popup ||
        event.data?.type !== "spid-login" || processing) return;
      if (event.data.requestId !== requestId && !(event.data.error && !event.data.requestId)) return;
      processing = true;
      clearInterval(timer);
      try {
        if (event.data.error) {
          throw new Error(loginErrorMessage(event.data.error) +
            (session ? " La sessione precedente non e' stata revocata." : ""));
        }
        if (typeof event.data.token !== "string") throw new Error("JWT non ricevuto");
        const receivedToken = event.data.token;
        const current: AppSession = await jsonResponse(await fetch("/api/session", {
          headers: { Authorization: `Bearer ${receivedToken}` },
        }));
        setToken(receivedToken);
        setSession(current);
      } catch (error) {
        setError(error instanceof Error ? error.message : "Errore durante il login");
      } finally {
        cleanup();
      }
    }

    window.addEventListener("message", onMessage);
    const timer = setInterval(() => {
      if (!processing && popup.closed) {
        setError("Login annullato o scaduto. La sessione precedente non e' stata revocata.");
        cleanup();
      }
    }, 500);
    const timeout = setTimeout(() => {
      if (!processing) {
        setError("Login scaduto. La sessione precedente non e' stata revocata.");
        cleanup();
      }
    }, 300_000);
    cancelLogin.current = cleanup;
    try {
      const result = await jsonResponse(await fetch("/api/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ level, requestId }),
      }));
      if (typeof result.url !== "string") throw new Error("URL di autorizzazione mancante");
      popup.location.href = result.url;
    } catch (error) {
      setError(error instanceof Error ? error.message : "Impossibile avviare il login");
      cleanup();
    }
  }

  async function logout() {
    setBusy(true);
    setError("");
    try {
      const response = await fetch("/api/logout", {
        method: "POST", headers: { Authorization: `Bearer ${token}` },
      });
      if (!response.ok) await jsonResponse(response);
      setToken(null);
      setSession(null);
    } catch (error) {
      setError(error instanceof Error ? error.message : "Logout non completato");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main>
      <header>
        <p className="eyebrow">NEXT.JS + BETTER AUTH</p>
        <h1>SPID OIDC Playground</h1>
        <p>JWT asimmetrici, sessioni persistenti e revoca su Redis.</p>
      </header>
      {error && <p className="error" role="alert">{error}</p>}
      <section aria-labelledby="session-title">
        <h2 id="session-title">Sessione</h2>
        <p role="status">{session
          ? session.provider === "magic-link" ? "Utente autenticato - Magic link" : `Utente autenticato - SPID ${session.level}`
          : "Utente non autenticato"}</p>
        {session ? <>
          <p>Scadenza assoluta: <time dateTime={session.expires}>{session.expires}</time></p>
          <pre aria-label="Dettagli della sessione">{JSON.stringify(session, null, 2)}</pre>
          <button className="secondary" disabled={busy} onClick={logout}>Logout e revoca</button>
        </> : <p>Effettua il login per visualizzare i dettagli della sessione.</p>}
      </section>
      <section aria-labelledby="login-title">
        <h2 id="login-title">Login</h2>
        <div className="actions">
          {SPID_LEVELS.map((level) => (
            <button key={level} disabled={busy} onClick={() => login(level)}>Login con SPID {level}</button>
          ))}
        </div>
        <p className="note">
          Il JWT resta solo in memoria: ricaricando la pagina si perde il login.
          Ogni login crea una sessione di un&apos;ora senza revocare la precedente.
          Il logout revoca tutti i JWT della sessione corrente, non esegue il logout dall&apos;IdP.
        </p>
      </section>
    </main>
  );
}
