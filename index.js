import express from "express";
import fetch from "node-fetch";

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// CORS
const ALLOW_ORIGIN = process.env.CORS_ORIGIN || "*";
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", ALLOW_ORIGIN);
  res.setHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type, Authorization, x-adec-key"
  );
  if (req.method === "OPTIONS") return res.status(204).end();
  next();
});

// New homepage route
app.get("/", (req, res) => {
  res.type("text/plain").send(
    "✅ ADEC API is live.\n\nAvailable endpoints:\n- GET /health\n- POST /forms/submit"
  );
});

// Health check
app.get("/health", (req, res) => res.json({ ok: true }));

// Form submission
app.post("/forms/submit", async (req, res) => {
  if (process.env.ADEC_KEY && req.get("x-adec-key") !== process.env.ADEC_KEY) {
    return res.status(401).json({ ok: false, error: "Unauthorized" });
  }
  const { name, email, phone, message, role } = req.body || {};
  if (!name || !email)
    return res
      .status(400)
      .json({ ok: false, error: "Missing name/email" });

  // Forward to n8n if configured
  if (process.env.N8N_WEBHOOK_URL) {
    try {
      await fetch(process.env.N8N_WEBHOOK_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ source: "ADEC", ...req.body }),
      });
    } catch (e) {
      console.error("n8n forward failed:", e);
    }
  }

  res.json({ ok: true, received: { name, email, phone, role } });
});

// Start server
const port = process.env.PORT || 8080;
app.listen(port, () =>
  console.log("ADEC backend running on port " + port)
);
