# Cleanup checklist

Do these in order, only after each stage is proven.

## A. Right after the first successful real login

- [ ] **Delete the one-off files**: `corex-auth-server-v2.patch`, `corex-auth-server-v2.zip`, any `backup.sql`, `*-backup.json`, `response.json`.
- [ ] **Delete the keypair file** `.corex-client-key.json` (a private key; also git-ignored).
- [ ] **Postman**: clear secret values from the environment or delete it; make sure it was never synced to a team workspace.
- [ ] **Secrets hygiene**: if your Upstox API secret, a CoreX client key or `COREX_STATE_KEY` was ever pasted into a chat, screenshot, issue or shared workspace, rotate it (Upstox console for the app secret; `npx wrangler secret put COREX_STATE_KEY` for the state key; issue a new client key with `npm run create-client` and revoke the old one in the dashboard).
- [ ] **Git**: confirm `git status` shows no secrets/backup files, commit, merge your `v2` branch into `main`, and deploy from `main` (`npm run deploy`).
- [ ] **Unused dependency**: `npm uninstall cloudflare` (nothing imports it). Run `npm test` afterwards.
- [ ] **Local state**: `.wrangler/` and `.dev.vars` are git-ignored; keep `.dev.vars` private or delete it when not developing.

## B. Remove API v1 (when no client uses it)

Check the dashboard: filter sessions and confirm no new rows say **v1 (legacy)** for a few weeks.

- [ ] Delete `server/services/auth-sessions.service.js` and `server/routes/auth.routes.js`.
- [ ] In `server/app.js` remove the `/api/v1/auth` import and `app.use`.
- [ ] In `server/routes/callbacks/broker-callback.routes.js` remove the "v1 (deprecated)" branch and the `/complete` compatibility route, plus the v1 imports.
- [ ] In `server/middleware/request-logger.js` remove the v1 `result` pattern in `normalizePath`.
- [ ] In `test/e2e.test.mjs` remove the "v1 flow still works" test.
- [ ] In `public/index.html` remove the two v1 rows from the endpoint table; in `public/app.js` the `v1 (legacy)` label is harmless but can go.
- [ ] Delete `docs/api-v1-deprecated.md` and its link in the README.
- [ ] **Database:** copy `docs/drafts/0005_drop_v1_columns.sql.draft` to `db/migrations/0005_drop_v1_columns.sql`. It drops `state_hash`, `retrieval_secret_hash`, `authorization_code` and deletes leftover v1 rows (the draft was tested against the real migrations).
      Then take a Time Travel bookmark first (`npx wrangler d1 time-travel info corex-db`), apply (`npx wrangler d1 migrations apply corex-db --remote`), and deploy.
      Also remove `authorization_code` references: in `server/services/admin-dashboard.service.js`, `client-admin.service.js`, and `maintenance.service.js` (they set `authorization_code = NULL`; the dashboard's `has_authorization_code` should test only `result_ciphertext`).
- [ ] Run `npm test` and one real login again.

## C. Optional tidy-ups

- [ ] Placeholder broker labels (`fyers`, `zerodha`, `angelone`) in `public/auth-response.js` and `server/routes/auth-response.routes.js` can be deleted until those brokers exist; unknown brokers get an automatic label.
- [ ] Decide log retention (defaults: request logs 30 days, finished sessions 90 days in `maintenance.service.js`).
- [ ] If you later add brokers, follow [adding-a-broker.md](./adding-a-broker.md); no other cleanup is needed.

## Keep

`test/`, `tools/`, `scripts/`, `docs/`: they are part of the project's blueprint and operations.
