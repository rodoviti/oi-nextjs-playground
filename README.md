# SPID OIDC Playground

PoC minimale in Next.js (App Router), TypeScript e Auth.js: login OIDC con livello
minimo SPID L2/L3 e sessioni JWE stateless con scadenza assoluta di **1 ora**.
Non richiede database.

## Avvio

Usare Node.js >= 20.19 (consigliato Node.js 22 LTS).

```sh
npm ci
```

Configurare le variabili nell'ambiente del processo o, in locale, nel proprio
`.env.local` non versionato:

| Variabile | Descrizione |
| --- | --- |
| `AUTH_URL` | URL pubblico dell'app, in locale `http://localhost:3000` |
| `AUTH_SECRET` | Segreto casuale di almeno 32 byte, generabile con `openssl rand -base64 32` |
| `OIDC_ISSUER` | Issuer dell'IdP, con discovery OIDC standard |
| `OIDC_CLIENT_ID` | Client ID registrato presso l'IdP |
| `OIDC_CLIENT_SECRET` | Client secret, da conservare solo sul server |
| `OIDC_ACR_L2` | Opzionale; default `https://www.spid.gov.it/SpidL2` |
| `OIDC_ACR_L3` | Opzionale; default `https://www.spid.gov.it/SpidL3` |

I valori `acr` devono coincidere con quelli accettati e restituiti dall'IdP.
L'issuer deve usare HTTPS; HTTP e' consentito solo su `localhost` per i test.
Non inserire segreti in variabili `NEXT_PUBLIC_*` o nel repository.
Il file di esempio delle variabili non e' incluso per le restrizioni di accesso
dell'ambiente in cui e' stata creata la PoC.

Registrare **entrambi** i redirect URI sullo stesso client OIDC:

```text
http://localhost:3000/api/auth/callback/spid-l2
http://localhost:3000/api/auth/callback/spid-l3
```

In produzione sostituire l'origine con quella HTTPS effettiva e aggiornare
`AUTH_URL`. L'app assume un confidential client con autenticazione al token
endpoint `client_secret_basic`, Authorization Code Flow, PKCE S256 e supporto
a `prompt=login`. Richiede gli scope `openid profile email`; i dati identificativi
visualizzati provengono dall'ID token. Una configurazione SPID/CIE con client
assertion, PAR o request object firmati richiede un'integrazione specifica, non
compresa in questa PoC OIDC generica.

```sh
npm run dev
```

Aprire <http://localhost:3000>. La stessa pagina mostra lo stato di autenticazione,
i dettagli della sessione e i pulsanti **Login con SPID L2** / **Login con SPID L3**.
Per eseguire la build di produzione: `npm run build && npm start`.

## Login e step-up

- Due provider Auth.js (`spid-l2` e `spid-l3`) condividono issuer e credenziali:
  inviano rispettivamente `acr_values` L2 e L3 e `prompt=login`.
- Auth.js gestisce il flusso OIDC, i controlli su issuer/audience/nonce e i controlli
  state/PKCE. Il callback verifica anche il claim **`acr` dell'ID token**:
  L3 soddisfa una richiesta L2, mentre L2 non soddisfa L3. Claim assenti o
  sconosciuti sono rifiutati. Il livello mostrato e' quello effettivamente ottenuto,
  non quello del pulsante selezionato.
- Lo step-up L2 -> L3 e' soltanto una **nuova login**. Non vengono invocati logout,
  revoche o endpoint di fine sessione dell'IdP.
- Durante il redirect la sessione corrente rimane disponibile. Al successo il
  browser riceve un nuovo cookie, che sostituisce quello precedente. Il vecchio
  JWE non viene conservato nell'interfaccia, ma resta valido se gia' posseduto da
  un altro client, fino alla sua scadenza originaria.
- Un annullamento, un errore OIDC o un livello insufficiente non revoca la
  sessione precedente. L'interfaccia mostra un errore; i dettagli diagnostici
  rimangono nei log del server.

Una nuova login L2 dopo L3 puo' sostituire la sessione con una di livello inferiore:
non e' implementata una policy che impedisca il downgrade.

## Sessione: JWE, TTL fisso, nessun rinnovo

La strategia Auth.js e' `jwt`: il cookie contiene un **JWE cifrato e autenticato**
con l'implementazione standard Auth.js (`dir` / `A256CBC-HS512`), non un JWT in
chiaro. Il cookie e' HttpOnly, SameSite=Lax e Secure su HTTPS.

Ogni login riuscita imposta `sessionStartedAt` e `sessionExpiresAt` a distanza di
3.600 secondi. Il solo `session.maxAge` non basta: Auth.js normalmente rinnova
la scadenza quando legge la sessione. Gli override `encode`/`decode` mantengono
invece la scadenza assoluta nel JWE, rifiutandolo dal secondo esatto di scadenza,
anche rispetto alla tolleranza temporale predefinita della libreria.
La risposta sessione mostra la stessa scadenza assoluta.

Auth.js puo' riemettere il cookie e aggiornarne la scadenza del browser, ma **non**
estende la validita' del JWE. Letture della sessione e aggiornamenti client non
estendono il TTL; solo una nuova autenticazione crea una nuova ora di validita'.
La scadenza della sessione dell'app e' indipendente da quella dei token dell'IdP:
non si eseguono refresh token o chiamate API protette.

Il JWE contiene solo identita' minima e metadati di sessione: access token,
refresh token e ID token non sono conservati ne' esposti dalla UI.
**Logout locale** cancella il cookie corrente, senza Single Logout e senza
revocare eventuali copie dei JWE precedenti. E' una conseguenza intenzionale
della gestione stateless richiesta, non un meccanismo di revoca.

## Verifiche

```sh
npm run lint
npm run typecheck
npm test
npm run build
npx playwright install chromium
npm run test:e2e
```

I test unitari coprono cifratura, deadline esatta, assenza di sliding expiration
e mapping dei livelli. I test browser usano un IdP locale sintetico con discovery,
token endpoint, ID token firmati, nonce e PKCE: coprono login L2/L3, sopravvivenza
del vecchio JWE, logout locale, cancellazione dello step-up e rifiuto di `acr`
insufficiente/assente. Non richiedono credenziali o connessioni a un IdP reale.
Il mock si avvia solo tramite Playwright, non fa parte dell'applicazione.

## Note

Auth.js e' il pacchetto `next-auth`, fissato alla versione `5.0.0-beta.32` per le
API App Router usate qui. E' una prerelease: valutarne gli aggiornamenti prima
di un uso produttivo. Questa PoC non e' un'implementazione completa del profilo
normativo SPID OpenID Connect e non include accreditamento o configurazione IdP.
