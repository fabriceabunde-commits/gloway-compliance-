# Gloway Compliance — backend foundation (NOT LIVE)

This is a **deployment scaffold**, not a production-ready customer portal. The public website currently has a local-only demonstration form. No customer information is sent to this Worker until a deliberate, tested frontend integration is made.

## Architecture
- Cloudflare Worker handles API routes.
- D1 stores minimal intake information and workflow status.
- Cloudflare Turnstile is mandatory on public intake.
- Admin routes require a **verified** Cloudflare Access JWT and an email allowlist.
- No FDA login passwords, registration PINs, identity documents, file uploads or payment details are accepted.
- FDA facility registration is free; Gloway charges only for its own assistance services.

## Deployment checklist (must complete before accepting real customers)
1. Create a D1 database in Cloudflare, bind it as `DB` and apply `schema.sql`.
2. Create a Turnstile widget restricted to `compliance.gloway.trade`, then store its secret with Wrangler (never in GitHub).
3. Create a Cloudflare Access application protecting the **admin API route**, configure `ACCESS_TEAM_DOMAIN`, `ACCESS_AUD`, and `ADMIN_EMAILS`. Protect `/api/admin/*` with an Access policy; server-side JWT verification is defense in depth.
4. Set `ALLOWED_ORIGIN` to the exact website origin and configure an API hostname (for example `api-compliance.gloway.trade`). The Worker rejects other browser origins; CORS is not authentication.
5. Add rate limits/WAF rules to public intake, validate deployment against abuse and failure scenarios, configure monitoring and backups, and publish privacy/retention/consent policies.
6. Test in staging with **fictional data only**, including access denial, duplicate requests, Turnstile failures, auditability and email notifications.
7. Only then connect the public frontend to the API, and clearly announce when submissions are live.

## API contract
- `GET /api/health` — health check
- `POST /api/applications` — JSON with `business,country,contact,email,service,notes,consent:true,turnstileToken`; returns a case reference.
- `GET /api/admin/applications` — Cloudflare Access-protected case list.
- `PATCH /api/admin/applications/:uuid/status` — Access-protected workflow stage update.

## Remaining production requirements
Authenticated manufacturer portal, customer case lookup, audit trails for all status changes, notifications, privacy/retention policy, secure document handling (R2 with authorization), operational backups, and legal/compliance review. **Do not enable sensitive uploads or represent this as a complete FDA filing system.**
