# Deployment

Production: https://phishexplain-nlp.vercel.app — Vercel project `phishexplain-nlp`, connected to GitHub `Arungharami/PhishExplain-NLP`. **Every push to `main` deploys automatically**; do not create a second project.

## How Vercel builds this project

- No framework and no build script. Vercel serves the repository root as static files with `cleanUrls: true` and bundles each file in `api/` as a Node.js function (dependencies traced from imports).
- `package.json` dependencies are installed, but the browser uses the committed `vendor/` builds, so no build step is needed.
- `.vercelignore` excludes `tests/`, `scripts/`, `.github/` and `node_modules/` from the upload.
- Security headers and per-route CSP live in `vercel.json`.

## Environment variables

All optional (see `.env.example`). With none configured the site works fully: the scanner is local, and `/api/reputation` and `/api/ai-analysis` report `available: false`.

| To enable | Set |
|---|---|
| Reputation lookups | `SHIELD_ACCESS_KEY` + any of `GOOGLE_SAFE_BROWSING_API_KEY`, `URLHAUS_AUTH_KEY`, `VIRUSTOTAL_API_KEY` |
| AI analysis | `SHIELD_ACCESS_KEY` + `OPENAI_API_KEY` (optional `SHIELD_AI_MODEL`) |
| Durable rate limits | `UPSTASH_REDIS_REST_URL` + `UPSTASH_REDIS_REST_TOKEN` (or Vercel KV vars) |
| Research transformer | `OPENAI_API_KEY` + `PHISHEXPLAIN_RESEARCH_KEY` |

Set them in Vercel → Settings → Environment Variables (Production), then redeploy.

## Release checklist

1. `npm ci && npm run check && npm test && npm run test:e2e` locally.
2. Push to `main` (or merge a PR). GitHub Actions runs the same checks with Chrome.
3. Confirm the Vercel commit status is `success` for the pushed SHA:
   `gh api repos/Arungharami/PhishExplain-NLP/commits/<sha>/status`
4. Smoke-test production:
   ```bash
   for p in / /security/ /security/dashboard/ /security/links/ /security/headers/ /security/analysis/ /security/reports/ /security/settings/ /nlp/ /lab/ /annotation/ /evaluation/ /course/ /shield.js /shield.css /vendor/postal-mime.js /vendor/tldts.js /api/reputation /api/ai-analysis /api/infer; do
     echo "$(curl -s -o /dev/null -w '%{http_code}' https://phishexplain-nlp.vercel.app$p) $p"; done
   curl -sI https://phishexplain-nlp.vercel.app/security/ | grep -i content-security-policy
   ```
5. Run the browser suite against production if needed: open `/security/`, run the "Credential phish" sample, export JSON.

## Rollback

Vercel → Deployments → select the previous production deployment → "Promote to Production" (instant), then revert the commit on `main`.

## Local development

```bash
npm ci
npm run dev            # http://127.0.0.1:4173 — static + /api/* with vercel.json headers (CSP enforced)
```

Environment variables for local API testing are read from your shell (the dev server does not load `.env` files).
