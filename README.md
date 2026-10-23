# SPID OIDC Playground

PoC Next.js App Router / TypeScript con Better Auth `1.7.12`, login SPID L2/L3,
sessioni persistenti su **PostgreSQL** e **JWT/JWS asimmetrici RS256** da un'ora.
Ogni API protetta verifica firma, issuer, audience, scadenza e revoche su **Redis**.
Non vengono usati cookie di sessione, JWE, localStorage o sessionStorage.

## Avvio

Usare Node.js >= 20.19 (consigliato Node.js 22).

```sh
npm ci
```

Configurare nell'ambiente del processo o in `.env.local` non versionato:

| Variabile | Descrizione |
| --- | --- |
| `BETTER_AUTH_URL` | Origine pubblica: `http://localhost:3000` in locale, `https://localhost:3000` con Traefik |
| `BETTER_AUTH_SECRET` | Segreto casuale di almeno 32 caratteri, generabile con `openssl rand -base64 32`; protegge anche le chiavi private JWT nel database |
| `DATABASE_URL` | Connessione PostgreSQL, ad esempio `postgres://utente:password@localhost:5432/playground` |
| `REDIS_URL` | Redis per revoche delle sessioni, ad esempio `redis://localhost:6379` |
| `OIDC_ISSUER` | Issuer IdP con discovery standard: HTTPS, salvo HTTP su localhost per i test |
| `OIDC_CLIENT_ID` | Client OIDC registrato presso l'IdP |
| `OIDC_CLIENT_SECRET` | Client secret, solo sul server |
| `OIDC_ACR_L2` | Opzionale: default `https://www.spid.gov.it/SpidL2` |
| `OIDC_ACR_L3` | Opzionale: default `https://www.spid.gov.it/SpidL3` |

Better Auth legge automaticamente URL e segreto: nessuna opzione `baseURL` o
`secret` custom. La validazione del segreto resta quella della libreria:
in produzione il valore predefinito viene rifiutato; valori corti o a bassa
entropia generano avvisi. Non inserire segreti in `NEXT_PUBLIC_*` o Git.
Usare credenziali URL-encoded nelle connection string.

Con PostgreSQL e Redis disponibili:

```sh
npm run db:migrate
npm run dev
```

Lo script migrazioni carica `.env.local` se presente. Le migrazioni SQL
versionate in [migrations/](./migrations/) sono eseguite in transazione, con
lock e registro `app_migrations`. Non vengono applicate implicitamente all'avvio
dell'app, non creano utenti demo e non cancellano sessioni.

Registrare sullo stesso client OIDC entrambi i callback:

```text
http://localhost:3000/api/auth/callback/spid-l2
http://localhost:3000/api/auth/callback/spid-l3
```

In produzione usare l'origine HTTPS effettiva e impostare `BETTER_AUTH_URL`.
Il client deve supportare Authorization Code Flow, PKCE S256,
`client_secret_basic`, `prompt=login`, nonce, discovery e ID token firmati.
La configurazione richiede lo scope `openid`; l'IdP deve comunque restituire
`sub`, `acr` ed `email` nell'ID token. Il parametro `idp` mantiene la selezione
UAT configurata in [src/auth.config.ts](./src/auth.config.ts).
L'issuer configurato e il subject identificano l'utente; l'email da sola non
autorizza il collegamento di un account.

Se il login viene rifiutato con `IdentityMismatch`, l'identita' OIDC non
corrisponde all'utente gia' associato. Non modificare il binding per aggirare
il controllo: verificare l'account usato presso l'IdP e la stabilita' del suo
subject. I log riportano solo l'esito dei confronti di issuer/subject e
l'esistenza dell'utente, senza registrarne i valori.

## Flusso Bearer-only nel browser

1. La UI apre un popup e genera un identificativo casuale di login in memoria.
2. `POST /api/login` riceve livello e identificativo, avvia Better Auth e imposta
   esclusivamente i cookie **temporanei OIDC** necessari a state/PKCE/nonce.
3. Il callback verifica l'ID token e il livello effettivo `acr`, poi persiste
   utente, associazione account e nuova sessione PostgreSQL.
4. Better Auth firma il JWT con le sue chiavi persistenti direttamente al
   termine del callback. La risposta HTML, non memorizzabile e protetta da
   CSP con nonce, invia JWT e identificativo alla pagina principale tramite
   `postMessage` limitato all'origine dell'app, poi chiude il popup.
5. La UI verifica origine, finestra mittente e identificativo del login;
   verifica il JWT tramite `/api/session` e lo conserva in memoria.
6. Le richieste successive usano `Authorization: Bearer <JWT>`.

Non esistono uno scambio applicativo `/api/token` o codici di handoff Redis.
Il PKCE del flusso OIDC verso l'IdP rimane attivo.

Il JWT non transita in URL, cookie o storage persistente e non e' mostrato
nella UI. Rimane nello stato JavaScript della pagina: **un refresh o la chiusura
della pagina perde il login**, senza revocare automaticamente la sessione.
Occorre consentire i popup; l'IdP deve consentire il ritorno alla finestra
chiamante senza policy che ne eliminino l'opener. Il login OIDC richiede
comunque cookie transitori: Bearer-only non significa browser senza cookie.

Le credenziali in memoria restano accessibili in caso di XSS: mantenere HTTPS,
dipendenze aggiornate e protezioni frontend adeguate. Non registrare il corpo
della risposta del callback, che contiene il JWT, nei log dei proxy.
`/api/login` accetta solo l'origine configurata.
Non e' prevista una policy CORS per frontend di terzi.

## Sessioni, JWT e step-up

- Ogni login riuscita crea una sessione distinta con `createdAt` ed `expiresAt`
  distanti esattamente **3.600 secondi**, senza rinnovo o refresh token.
- `subject`, issuer OIDC, livello, `acr`, provider e `authTime` sono salvati
  **sulla sessione**, non sul profilo utente condiviso. Un login L3 non modifica
  i privilegi di una sessione L2 precedente.
- Lo step-up apre una nuova login, senza logout preventivo. Cancellazione,
  errori e `acr` insufficiente mantengono il JWT precedente in memoria.
  L3 soddisfa L2; L2 non soddisfa L3. `acr` assenti o sconosciuti sono rifiutati.
  Un nuovo login L2 dopo L3 e' consentito.
- L2/L3 possono collegarsi allo stesso utente solo quando issuer e subject
  coincidono con quelli persistiti; email uguale con subject diverso e' rifiutata.
- Il plugin `jwt()` gestisce generazione e firma RS256, chiavi private cifrate
  nel database ed esposizione delle sole chiavi pubbliche su `/api/auth/jwks`.
  Non cambiare `BETTER_AUTH_SECRET` senza una strategia di rotazione.
- Il JWS include `sub`, `sid` (session ID), `jti`, `iat`, `exp`, `iss`, `aud`
  e identita'/metadati minimi della sessione. `iss` e `aud` sono l'origine
  pubblica dell'app. `iat` ed `exp` riflettono la sessione originaria, non
  l'istante di firma: emettere il JWT piu' tardi non estende l'ora.
- **Un JWS e' firmato, non cifrato**: il payload e' leggibile dal possessore.
  Access token, refresh token e ID token dell'IdP non sono conservati nei JWT
  o negli account PostgreSQL, ne' esposti nella UI.
- Il token opaco interno di Better Auth resta nel database, non viene
  consegnato al browser e non autentica le API pubbliche tramite cookie.

Il plugin JWT non sostituisce da solo le sessioni Better Auth: il codice
custom e' limitato alla consegna Bearer-only, ai metadati per sessione e alla
revoca richiesta. I normali endpoint cookie `/api/auth/get-session`,
`/api/auth/token`, modifica utente e collegamento account non sono esposti.

## API e revoca

| Endpoint | Utilizzo |
| --- | --- |
| `GET /api/auth/jwks` | JWKS pubblico, nessun token richiesto |
| `POST /api/login` | Avvio login popup, JSON `{ "level": "L2", "requestId": "..." }` |
| `POST /api/magic-link/generate` | Genera un JWE monouso, richiede Bearer JWT valido |
| `POST /api/magic-link` | Login custom, JSON `{ "jwe": "..." }`, restituisce `{ "token", "session" }` |
| `GET /api/session` | Identita' e metadati del JWT, richiede Bearer |
| `GET /api/example` | Esempio di API protetta, richiede Bearer |
| `POST /api/logout` | Revoca della sessione corrente, richiede Bearer |

Per servizi e client mobili che gia' possiedono un JWT:

```sh
curl -H "Authorization: Bearer $TOKEN" https://example.test/api/example
curl -X POST -H "Authorization: Bearer $TOKEN" https://example.test/api/logout
```

Le API verificano RS256 con le chiavi del plugin, issuer/audience, claim
obbligatori e scadenza esatta senza clock tolerance. Consultano Redis ad
**ogni richiesta** per la chiave `revoked:<sid>`. Una verifica offline via
JWKS e' necessaria ma **non sufficiente**: un servizio esterno deve controllare
anche la denylist condivisa per rispettare il logout.

Il logout scrive prima la revoca Redis con scadenza assoluta `exp`, poi marca
`revokedAt` nel record PostgreSQL. Revoca **tutti i JWT della stessa sessione**,
non quelli di altre login e non la sessione IdP. Il record PostgreSQL viene
conservato per una futura correlazione con audit log; gli audit log non sono
ancora implementati. La UI dimentica il JWT solo dopo il successo del logout.

Redis e' un servizio dedicato alla denylist e ai magic link monouso, non la
`secondaryStorage` delle sessioni Better Auth: le sessioni restano in PostgreSQL.
Se Redis o PostgreSQL necessari all'operazione non sono disponibili, le API
restituiscono **503**, non autorizzano richieste e non simulano un logout riuscito.
La revoca Redis resta efficace anche se fallisce il successivo aggiornamento DB;
il logout e' ripetibile per completare quell'aggiornamento.

Redis contiene stato di autorizzazione, **non una cache sacrificabile**:
non svuotarlo, non ripristinare snapshot obsoleti e non usare eviction.
Lo stack locale usa volume persistente, AOF con `appendfsync always` e
`noeviction`. La perdita dei dati Redis puo' rendere nuovamente accettabili
JWT gia' revocati fino alla loro scadenza; prima di riaprire il traffico,
ricostruire la denylist dalle sessioni con `revokedAt` o attendere la scadenza
di tutti i JWT emessi. In produzione servono autenticazione/TLS, backup e
una strategia di disponibilita'/ripristino per entrambi i database.

## Login custom tramite magic link

Applicare prima `npm run db:migrate`: la migrazione `002_magic_link.sql`
consente sessioni senza livello SPID, mantenendo invariati i vincoli per OIDC.

Il provider custom usa le stesse sessioni PostgreSQL, firma RS256 Better Auth,
JWKS e revoca dei JWT OIDC, senza discovery o contatto con l'IdP.
Non invia email e non genera URL: il JWE e' una credenziale da consegnare
tramite un canale sicuro e presentare nel body JSON.

1. `POST /api/magic-link/generate` con `Authorization: Bearer <JWT>` verifica
   il JWT attivo e la sessione sorgente. Risponde con
   `{ "jwe": "...", "expiresAt": "..." }`; il JWE dura **86.400 secondi**.
2. `POST /api/magic-link` con `Content-Type: application/json` e
   `{ "jwe": "..." }` riscatta la credenziale una sola volta.
3. Viene creata una nuova sessione indipendente di **3.600 secondi** e
   restituito `{ "token": "...", "session": { ... } }`.

Il JWE usa `dir`/`A256GCM`, con chiave derivata tramite HKDF-SHA256 dal segreto
risolto nativamente da Better Auth (`BETTER_AUTH_SECRET`) e contesto dedicato.
E' cifrato e autenticato, non un JWS firmato. Issuer, audience specifica,
purpose, tipo, scadenza e riferimento alla sessione vengono verificati.
Non contiene il JWT sorgente o token dell'IdP.

La sorgente puo' essere scaduta al riscatto, ma deve esistere e non essere
revocata. Il record PostgreSQL conservato permette di rilevare una revoca
anche dopo la scadenza della relativa chiave Redis.
Dopo il riscatto, la nuova sessione ha revoca e scadenza indipendenti:
revocare la sorgente non revoca retroattivamente la nuova sessione.

Il JWT mantiene struttura, identita', issuer/audience e durata dei JWT OIDC,
ma `session.provider` e' `magic-link`, `session.level` e' `null` e
`session.acr`/`session.authTime` sono assenti. Non attesta SPID L2/L3:
i servizi che richiedono quel livello devono rifiutarlo.
Un JWT magic-link attivo puo' generare a sua volta un nuovo magic link;
questo flusso consente quindi di proseguire l'accesso oltre la login SPID
originaria senza attestare una nuova autenticazione SPID.

Redis conserva `magic-link:<jti>` fino alla scadenza; il consumo atomico
impedisce replay e riscatti concorrenti. Se un errore avviene dopo il consumo,
il link resta consumato e l'API segnala il fallimento: non viene ripristinato.
Gli errori infrastrutturali restituiscono 503. Non registrare JWE/JWT o body
degli endpoint nei log; non inserirli negli URL. Non esiste autenticazione
tramite cookie ne' viene introdotto storage persistente nel frontend.

## Dev Container e HTTPS

Richiede Docker Compose v2 e VS Code Dev Containers. Prima di aprire il
container, configurare `POSTGRES_PASSWORD` nell'ambiente dell'host/Compose
(ad esempio un valore casuale ottenuto con `openssl rand -hex 32`).
Non versionare il valore. Le porte host **3000, 5433 e 6379** devono essere libere.

Lo stack [Compose](./.devcontainer/compose.yaml) avvia:

- PostgreSQL 17 e Redis 7.4, con health check, volumi persistenti e porte
  pubblicate soltanto su `127.0.0.1` per sviluppo/test dall'host
  (PostgreSQL su `5433`, Redis su `6379`);
- `certificates`, che genera certificati locali con mkcert;
- `app`, Dev Container Node.js 22, con `DATABASE_URL` e `REDIS_URL` interni;
- Traefik, che pubblica HTTPS su `127.0.0.1:3000` e inoltra HTTP a `app:3000`,
  inclusi WebSocket/HMR, senza socket Docker ne' dashboard.

Tutti i servizi sono collegati esplicitamente alla rete bridge `default`,
dichiarata nel Compose e isolata per progetto (`<progetto>_default`).
Tra container usare i nomi dei servizi, ad esempio `postgres:5432` e
`redis:6379`, non `localhost`. VS Code assegna il nome progetto
`<cartella>_devcontainer`: dai comandi Compose sull'host specificare lo stesso
nome con `-p` per gestire lo stack esistente.

Aprire **Dev Containers: Reopen in Container** o **Rebuild and Reopen in Container**.
`npm ci` e' eseguito alla creazione e `npm run db:migrate` a ogni avvio,
prima che il Dev Container sia pronto. Configurare le restanti variabili in
`.env.local`, incluso `BETTER_AUTH_URL=https://localhost:3000`, poi:

```sh
npm run dev -- --hostname 0.0.0.0
```

Aprire <https://localhost:3000> e registrare i callback HTTPS corrispondenti
presso l'IdP. L'IdP deve consentire localhost: lo stack non rende l'app pubblica.
Per usare un tunnel pubblico verso HTTP locale, cambiare `BETTER_AUTH_URL`
e registrare i callback della stessa origine prima di riavviare Next.js.

### Certificato HTTPS fidato

`certificates` genera automaticamente in `.devcontainer/certs/`:

- `localhost.pem` e `localhost-key.pem`, per localhost, 127.0.0.1 e ::1;
- `rootCA.pem`, certificato pubblico della CA da importare sull'host.

La chiave privata della CA rimane nel volume `mkcert-ca`, non e' montata
in app/Traefik. I certificati generati sono esclusi da Git. App e Traefik
attendono la generazione: un errore ne blocca l'avvio.

**Una sola volta**, importare `rootCA.pem` sul computer host/browser.
Dal terminale host, alla radice del repository:

Linux Debian/Ubuntu:

```sh
sudo cp .devcontainer/certs/rootCA.pem /usr/local/share/ca-certificates/oi-nextjs-playground.crt
sudo update-ca-certificates
```

macOS:

```sh
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain .devcontainer/certs/rootCA.pem
```

Windows PowerShell:

```powershell
Import-Certificate -FilePath .devcontainer/certs/rootCA.pem -CertStoreLocation Cert:\CurrentUser\Root
```

Firefox e alcuni browser Linux richiedono l'importazione nelle impostazioni
Certificati / Autorita'. Riavviare il browser. Non condividere `rootCA-key.pem`.
Eliminare il volume `mkcert-ca` richiede importare la nuova CA; la sola
riconnessione VS Code non rigenera i certificati.

```sh
docker compose -f .devcontainer/compose.yaml config --quiet
docker compose -f .devcontainer/compose.yaml logs certificates traefik
curl --cacert .devcontainer/certs/rootCA.pem https://localhost:3000/
```

Un 502 indica normalmente che Next.js non ascolta ancora su `0.0.0.0:3000`.
Per rigenerare i certificati senza cambiare CA:

```sh
docker compose -f .devcontainer/compose.yaml run --rm certificates
docker compose -f .devcontainer/compose.yaml restart traefik
```

## Verifiche

```sh
npm run lint
npm run typecheck
npm test
npm run build
npx playwright install --with-deps chromium
npm run test:e2e
```

Unit test e build non richiedono IdP, PostgreSQL o Redis attivi.
Per i test browser occorrono **database e Redis dedicati ai test**, mai quelli
di produzione. Playwright applica le migrazioni ma conserva i dati preesistenti.
Configurare `TEST_DATABASE_URL` e `TEST_REDIS_URL`; i default sono
`postgres://playground:test-only@localhost:5432/playground_test` e
`redis://localhost:6379`. Nel Dev Container usare gli hostname `postgres`
e `redis`, le proprie credenziali e un database separato creato per i test.
Le porte 3100 e 4100 devono essere libere.

Playwright avvia e ferma app di produzione e IdP sintetico, usa un solo worker
e non riutilizza server esistenti. Ricostruire l'app dopo ogni modifica.
La CI prepara PostgreSQL/Redis separati tramite servizi GitHub Actions.
I test coprono login e step-up, errori OIDC, binding issuer/subject, JWS/JWKS,
assenza di cookie di sessione e storage persistente, record DB e revoca al logout.
Gli unit test verificano anche deadline esatta, denylist ad ogni richiesta,
indisponibilita' Redis e consegna diretta del JWT con CSP e origine vincolata.

## Limiti e migrazione

Le vecchie sessioni JWE/Auth.js non sono compatibili: effettuare un nuovo login.
Non e' implementato un flusso di login nativo mobile/deep link, un'app mobile,
un OAuth Authorization Server per client terzi, audit log o pulizia schedulata
dei record PostgreSQL. Definire retention e raccolta audit prima della produzione.
La PoC non e' un'implementazione completa del profilo normativo SPID OIDC;
client assertion, PAR, request object firmati e accreditamento sono fuori ambito.
