# ADEC Backend (Secure resume intake)

**Features**
- Security headers (Helmet), CORS allow-list, rate-limit
- reCAPTCHA verification (v3/Enterprise token accepted)
- Resume upload to **private** Google Cloud Storage
- Metadata saved as JSON alongside resume with **encrypted PII**
- Admin endpoints with **Bearer token** to list apps and fetch **signed URL** for resumes

## Env vars
See `.env.example`. In Cloud Run, set vars & mount secrets.

## GCS
- Create a private bucket, enable **Uniform bucket-level access** (no object ACLs).
- Set IAM so the Cloud Run service account has `Storage Object Admin` on the bucket.

## Local dev
```bash
cp .env.example .env
npm i
npm run dev
