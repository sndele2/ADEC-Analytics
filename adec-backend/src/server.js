import express from "express";
import helmet from "helmet";
import cors from "cors";
import rateLimit from "express-rate-limit";
import multer from "multer";
import { z } from "zod";
import { Storage } from "@google-cloud/storage";
import mime from "mime-types";

import {
  initCrypto, encryptPII, decryptPII, verifyRecaptcha,
  nowIso, pickIp, makeId, sha256
} from "./util.js";

/* ------------------- Bootstrap ------------------- */
await initCrypto();
const app = express();
app.set("trust proxy", 1);

const {
  PORT = "8080",
  NODE_ENV = "production",
  CORS_ALLOW_ORIGINS = "",
  ADMIN_BEARER,
  GCS_BUCKET,
  GCS_SIGNED_URL_EXP_SECONDS = "900"
} = process.env;

if (!GCS_BUCKET) {
  console.warn("WARN: GCS_BUCKET not set. Uploads will fail.");
}

const storage = new Storage();
const bucket = GCS_BUCKET ? storage.bucket(GCS_BUCKET) : null;

app.use(helmet({
  contentSecurityPolicy: false, // handled on frontend / CDN
  crossOriginOpenerPolicy: { policy: "same-origin-allow-popups" }
}));
app.disable("x-powered-by");

const ALLOW = CORS_ALLOW_ORIGINS.split(",").map(s => s.trim()).filter(Boolean);
app.use(cors({
  origin(origin, cb) {
    if (!origin) return cb(null, true); // e.g., curl/postman
    return ALLOW.includes(origin) ? cb(null, true) : cb(new Error("CORS blocked"), false);
  },
  methods: ["POST", "GET", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "x-recaptcha-token"]
}));

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: false, limit: "1mb" }));

const limiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 150, // 150 req / 10 min / IP
  standardHeaders: true,
  legacyHeaders: false
});
app.use(limiter);

/* ------------------- Upload config ------------------- */
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 } // 10MB
});

const fileAllowed = (originalname, mimetype) => {
  const okExt = /\.(pdf|doc|docx)$/i.test(originalname || "");
  const okMime = [
    "application/pdf",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
  ].includes(mimetype);
  return okExt && okMime;
};

/* ------------------- Schemas ------------------- */
const applySchema = z.object({
  full_name: z.string().min(2).max(120),
  email: z.string().email(),
  phone: z.string().min(7).max(30).optional().nullable(),
  cover_letter: z.string().max(5000).optional().nullable(),
  job_code: z.string().max(64).optional().nullable(),
  recaptchaToken: z.string().min(10)
});

/* ------------------- Helpers ------------------- */
function requireAdmin(req, res, next) {
  const token = req.headers.authorization?.replace("Bearer ", "");
  if (!ADMIN_BEARER || token !== ADMIN_BEARER) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
}

function objPathFor(id) {
  // keep everything private in a single bucket with clear prefixes
  // resumes/<yyyy-mm>/<id>.<ext> and resumes-meta/<id>.json
  const ym = new Date().toISOString().slice(0, 7);
  return { folder: ym, meta: `resumes-meta/${id}.json` };
}

/* ------------------- Routes ------------------- */

// Health
app.get("/health", (req, res) => res.status(200).json({ ok: true, ts: nowIso() }));

/**
 * POST /api/careers/apply
 * multipart/form-data
 * fields: full_name, email, phone?, cover_letter?, job_code?, recaptchaToken
 * file: resume
 */
app.post("/api/careers/apply", upload.single("resume"), async (req, res) => {
  try {
    // 1) Basic validations
    const parse = applySchema.safeParse({
      ...req.body,
      recaptchaToken: req.headers["x-recaptcha-token"] || req.body.recaptchaToken
    });
    if (!parse.success) {
      return res.status(400).json({ error: "Invalid data", details: parse.error.issues });
    }
    const { full_name, email, phone, cover_letter, job_code, recaptchaToken } = parse.data;

    // 2) reCAPTCHA
    const ip = pickIp(req);
    const okCaptcha = await verifyRecaptcha(recaptchaToken, ip);
    if (!okCaptcha) return res.status(403).json({ error: "Failed reCAPTCHA" });

    // 3) File check
    if (!req.file) return res.status(400).json({ error: "Missing resume file" });
    const { originalname, mimetype, buffer } = req.file;

    if (!fileAllowed(originalname, mimetype)) {
      return res.status(415).json({ error: "Only PDF/DOC/DOCX are allowed" });
    }

    if (!bucket) return res.status(500).json({ error: "Storage not configured" });

    const id = makeId();
    const { folder, meta } = objPathFor(id);

    const ext = (originalname.match(/\.(pdf|doc|docx)$/i) || [])[0]?.toLowerCase() || "";
    const hash = sha256(buffer).slice(0, 16);
    const objectName = `resumes/${folder}/${id}-${hash}${ext}`;

    // 4) Upload resume (private by default with uniform bucket-level access)
    const file = bucket.file(objectName);
    await file.save(buffer, {
      contentType: mimetype,
      resumable: false,
      metadata: {
        metadata: {
          applicant_hash: sha256(email.toLowerCase()),
          created_at: nowIso(),
          job_code: job_code || "",
          av_status: "pending" // if you later add AV scanning, flip to "clean"
        }
      }
    });

    // 5) Store encrypted metadata JSON alongside (you can later move this into a DB)
    const emailEnc = encryptPII(email);
    const phoneEnc = encryptPII(phone || "");
    const metaObj = {
      id,
      created_at: nowIso(),
      ip,
      ua: req.headers["user-agent"] || "",
      job_code: job_code || null,
      full_name,                         // name is not strictly PII-sensitive; encrypt if you prefer
      email: emailEnc,
      phone: phoneEnc,
      cover_letter: (cover_letter || "").slice(0, 5000),
      resume_gcs_uri: `gs://${GCS_BUCKET}/${objectName}`
    };

    await bucket.file(meta).save(Buffer.from(JSON.stringify(metaObj, null, 2)), {
      contentType: "application/json",
      resumable: false
    });

    // 6) Respond with application id
    return res.status(201).json({ ok: true, id });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Server error" });
  }
});

/**
 * GET /api/admin/applications
 * List latest N application metadata (decrypted selectively)
 * Query: limit=<int: default 25>
 */
app.get("/api/admin/applications", requireAdmin, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit || "25", 10), 200);

    const [files] = await bucket.getFiles({
      prefix: "resumes-meta/",
      autoPaginate: false
    });

    // Most recent first
    files.sort((a, b) => (b.metadata?.updated || "").localeCompare(a.metadata?.updated || ""));

    const items = [];
    for (const f of files.slice(0, limit)) {
      const [buf] = await f.download();
      const meta = JSON.parse(buf.toString("utf8"));

      // Decrypt email/phone for admin view
      meta.email_plain = decryptPII(meta.email);
      meta.phone_plain = decryptPII(meta.phone);
      items.push(meta);
    }

    return res.json({ ok: true, count: items.length, items });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Server error" });
  }
});

/**
 * GET /api/admin/applications/:id/resume-url
 * Returns a short-lived signed URL to download the resume
 */
app.get("/api/admin/applications/:id/resume-url", requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { meta } = objPathFor(id);

    const [buf] = await bucket.file(meta).download();
    const metaObj = JSON.parse(buf.toString("utf8"));

    const gsUri = metaObj.resume_gcs_uri; // gs://bucket/path
    const [, , , ...pathParts] = gsUri.split("/"); // ["gs:", "", "bucket", "path", ...]
    const objectPath = pathParts.join("/");

    const [url] = await bucket.file(objectPath).getSignedUrl({
      action: "read",
      expires: Date.now() + Number(process.env.GCS_SIGNED_URL_EXP_SECONDS || 900) * 1000,
      responseDisposition: `attachment; filename="${id}.${mime.extension((await bucket.file(objectPath).getMetadata())[0].contentType) || "bin"}"`
    });

    return res.json({ ok: true, id, url, expires_in_seconds: Number(process.env.GCS_SIGNED_URL_EXP_SECONDS || 900) });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Server error" });
  }
});
/* ------------------- Start ------------------- */
app.listen(Number(PORT), () => {
  console.log(`ADEC backend running on :${PORT} (env=${NODE_ENV})`);
});

