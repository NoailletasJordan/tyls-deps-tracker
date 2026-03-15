require("dotenv").config();

// Validate required env vars
const REQUIRED_ENV = [
  "STRAPI_IMAGE", "STRAPI_REGISTRY_URL", "STRAPI_REGISTRY_USER", "STRAPI_REGISTRY_PASS",
  "FRONTEND_IMAGE", "FRONTEND_REGISTRY_URL", "FRONTEND_REGISTRY_USER", "FRONTEND_REGISTRY_PASS",
  "AUTH_USER", "AUTH_PASS",
  "PORT", "SCAN_CRON", "WEEKLY_CRON",
  "DISCORD_WEBHOOK", "DISCORD_MENTION",
];

const missing = REQUIRED_ENV.filter((key) => !process.env[key]);
if (missing.length > 0) {
  console.error(`Missing required env vars: ${missing.join(", ")}`);
  process.exit(1);
}

const crypto = require("crypto");
const fs = require("fs");
const express = require("express");
const path = require("path");

const DATA_DIR = path.join(__dirname, "data");
const NOTIFIED_VULNS_PATH = path.join(DATA_DIR, "notified-criticals.json");
const cron = require("node-cron");
const {
  scanAll,
  getLatestResults,
  getImages,
  getHistory,
  getScanDetail,
} = require("./scanner");

const app = express();
const PORT = process.env.PORT;
const SCAN_CRON = process.env.SCAN_CRON;
const DISCORD_WEBHOOK = process.env.DISCORD_WEBHOOK;
const AUTH_USER = process.env.AUTH_USER;
const AUTH_PASS = process.env.AUTH_PASS;

// Generate a secret at startup for signing tokens
const TOKEN_SECRET = crypto.randomBytes(32).toString("hex");

function createToken(username) {
  const payload = `${username}:${Date.now()}`;
  const sig = crypto.createHmac("sha256", TOKEN_SECRET).update(payload).digest("hex");
  return Buffer.from(`${payload}:${sig}`).toString("base64");
}

function verifyToken(token) {
  try {
    const decoded = Buffer.from(token, "base64").toString();
    const parts = decoded.split(":");
    const sig = parts.pop();
    const payload = parts.join(":");
    const expected = crypto.createHmac("sha256", TOKEN_SECRET).update(payload).digest("hex");
    return sig === expected;
  } catch {
    return false;
  }
}

// Scan status tracking
let scanStatus = { running: false, startedAt: null, images: [] };

// Build image configs from env vars
function getImageConfigs() {
  const configs = [];
  if (process.env.STRAPI_IMAGE) {
    configs.push({
      image: process.env.STRAPI_IMAGE,
      registryUrl: process.env.STRAPI_REGISTRY_URL,
      registryUser: process.env.STRAPI_REGISTRY_USER,
      registryPass: process.env.STRAPI_REGISTRY_PASS,
    });
  }
  if (process.env.FRONTEND_IMAGE) {
    configs.push({
      image: process.env.FRONTEND_IMAGE,
      registryUrl: process.env.FRONTEND_REGISTRY_URL,
      registryUser: process.env.FRONTEND_REGISTRY_USER,
      registryPass: process.env.FRONTEND_REGISTRY_PASS,
    });
  }
  return configs;
}

// Weekly summary — sends full vulnerability report regardless of severity
async function notifyWeeklySummary() {
  if (!DISCORD_WEBHOOK) return;

  const results = getLatestResults();
  if (results.length === 0) return;

  const mention = process.env.DISCORD_MENTION
    ? `<@${process.env.DISCORD_MENTION}>`
    : "";

  const lines = results.map((r) => {
    const s = r.summary || { CRITICAL: 0, HIGH: 0, MEDIUM: 0 };
    const total = s.CRITICAL + s.HIGH + s.MEDIUM;
    return `**${r.image}** — ${total} total (${s.CRITICAL} Critical, ${s.HIGH} High, ${s.MEDIUM} Medium)`;
  });

  const body = {
    content: mention,
    embeds: [
      {
        title: "\ud83d\udccb Weekly Vulnerability Report",
        description: lines.join("\n"),
        color: 0x3b82f6,
        timestamp: new Date().toISOString(),
      },
    ],
  };

  try {
    const res = await fetch(DISCORD_WEBHOOK, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!res.ok) console.error(`[discord] Weekly summary failed: ${res.status}`);
    else console.log("[discord] Weekly summary sent");
  } catch (err) {
    console.error(`[discord] Weekly summary error: ${err.message}`);
  }
}

// --- Notified vulnerabilities deduplication ---
// Stores { vulnIds: ["CVE-xxxx", ...] } so we only ping for NEW criticals.

function loadNotifiedVulns() {
  try {
    if (fs.existsSync(NOTIFIED_VULNS_PATH)) {
      return JSON.parse(fs.readFileSync(NOTIFIED_VULNS_PATH, "utf-8"));
    }
  } catch (err) {
    console.error(`[dedup] Failed to load notified vulns: ${err.message}`);
  }
  return { vulnIds: [] };
}

function saveNotifiedVulns(data) {
  try {
    if (!fs.existsSync(DATA_DIR)) {
      fs.mkdirSync(DATA_DIR, { recursive: true });
    }
    fs.writeFileSync(NOTIFIED_VULNS_PATH, JSON.stringify(data, null, 2));
  } catch (err) {
    console.error(`[dedup] Failed to save notified vulns: ${err.message}`);
  }
}

/**
 * Extract all critical vulnerability IDs from scan results.
 * Returns a Map of vulnId -> { image, title }
 */
function extractCriticalVulnIds(results) {
  const vulns = new Map();
  for (const r of results) {
    const trivyData = r.raw || r.trivy || {};
    const targets = trivyData.Results || [];
    for (const target of targets) {
      for (const vuln of target.Vulnerabilities || []) {
        if (vuln.Severity === "CRITICAL") {
          vulns.set(vuln.VulnerabilityID, {
            image: r.image,
            title: vuln.Title || vuln.VulnerabilityID,
          });
        }
      }
    }
  }
  return vulns;
}

// Send Discord alert only for NEW critical vulnerabilities
async function notifyCriticals(results) {
  if (!DISCORD_WEBHOOK) return;

  const currentVulns = extractCriticalVulnIds(results);
  if (currentVulns.size === 0) {
    // No criticals at all — clear the stored list
    saveNotifiedVulns({ vulnIds: [] });
    return;
  }

  const stored = loadNotifiedVulns();
  const alreadyNotified = new Set(stored.vulnIds);
  const newVulns = new Map();

  for (const [id, info] of currentVulns) {
    if (!alreadyNotified.has(id)) {
      newVulns.set(id, info);
    }
  }

  // Save the current full set so tomorrow we compare against today's state
  saveNotifiedVulns({ vulnIds: [...currentVulns.keys()] });

  if (newVulns.size === 0) {
    console.log(`[discord] ${currentVulns.size} criticals found but all already notified — skipping`);
    return;
  }

  console.log(`[discord] ${newVulns.size} new critical(s) out of ${currentVulns.size} total`);

  // Group new vulns by image for the message
  const byImage = new Map();
  for (const [id, info] of newVulns) {
    if (!byImage.has(info.image)) byImage.set(info.image, []);
    byImage.get(info.image).push(id);
  }

  const lines = [];
  for (const [image, ids] of byImage) {
    lines.push(`**${image}** — ${ids.length} new critical(s):\n${ids.map((id) => `  \`${id}\``).join("\n")}`);
  }

  const mention = process.env.DISCORD_MENTION
    ? `<@${process.env.DISCORD_MENTION}>`
    : "";

  const body = {
    content: mention,
    embeds: [
      {
        title: "\u26a0\ufe0f New Critical Vulnerabilities Detected",
        description: lines.join("\n\n"),
        color: 0xff0000,
        timestamp: new Date().toISOString(),
        footer: { text: `${currentVulns.size} total criticals (${currentVulns.size - newVulns.size} already known)` },
      },
    ],
  };

  try {
    const res = await fetch(DISCORD_WEBHOOK, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!res.ok) console.error(`[discord] Webhook failed: ${res.status}`);
    else console.log("[discord] Critical alert sent");
  } catch (err) {
    console.error(`[discord] Webhook error: ${err.message}`);
  }
}

app.use(express.json());

// Login endpoint (unprotected)
app.post("/api/login", (req, res) => {
  const { username, password } = req.body || {};
  if (username === AUTH_USER && password === AUTH_PASS) {
    const token = createToken(username);
    return res.json({ ok: true, token });
  }
  res.status(401).json({ ok: false, error: "Invalid credentials" });
});

// Auth middleware — protect API routes and static files
function authMiddleware(req, res, next) {
  // Skip auth if no credentials configured
  if (!AUTH_USER || !AUTH_PASS) return next();

  const authHeader = req.headers.authorization;
  if (authHeader?.startsWith("Bearer ")) {
    const token = authHeader.slice(7);
    if (verifyToken(token)) return next();
  }

  if (req.path.startsWith("/api/")) {
    return res.status(401).json({ ok: false, error: "Unauthorized" });
  }

  // For non-API routes, serve index.html (React handles the login UI)
  return next();
}

app.use(authMiddleware);
app.use(express.static(path.join(__dirname, "public")));

// Get latest scan results (one per image)
app.get("/api/results", (_req, res) => {
  try {
    const results = getLatestResults();
    res.json({ ok: true, results });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// List all scanned images
app.get("/api/images", (_req, res) => {
  try {
    const images = getImages();
    res.json({ ok: true, images });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// Get scan status
app.get("/api/status", (_req, res) => {
  res.json({ ok: true, ...scanStatus });
});

// Get scan history for a specific image
app.get("/api/history/:image", (req, res) => {
  try {
    const history = getHistory(req.params.image);
    res.json({ ok: true, image: req.params.image, history });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// Get full detail for a specific scan
app.get("/api/detail/:image/:file", (req, res) => {
  try {
    const detail = getScanDetail(req.params.image, req.params.file);
    if (!detail) {
      return res.status(404).json({ ok: false, error: "Scan not found" });
    }
    res.json({ ok: true, ...detail });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// Trigger a scan
app.post("/api/scan", (_req, res) => {
  if (scanStatus.running) {
    return res.status(409).json({ ok: false, error: "Scan already running" });
  }

  const configs = getImageConfigs();
  if (configs.length === 0) {
    return res
      .status(400)
      .json({ ok: false, error: "No images configured in .env" });
  }

  const images = configs.map((c) => c.image);
  scanStatus = { running: true, startedAt: new Date().toISOString(), images };
  res.json({ ok: true, message: "Scan started", images });

  // Run scan async, update status when done
  Promise.resolve()
    .then(() => scanAll(configs))
    .then((results) => notifyCriticals(results))
    .finally(() => {
      scanStatus = { running: false, startedAt: null, images: [] };
    });
});

app.listen(PORT, () => {
  console.log(`Deps Tracker running at http://localhost:${PORT}`);
  console.log(
    `Images: ${process.env.FRONTEND_IMAGE || "(not set)"}, ${process.env.STRAPI_IMAGE || "(not set)"}`
  );

  // Schedule daily scan
  if (cron.validate(SCAN_CRON)) {
    cron.schedule(SCAN_CRON, () => {
      const configs = getImageConfigs();
      if (configs.length === 0 || scanStatus.running) return;

      const images = configs.map((c) => c.image);
      console.log(`[cron] Starting scheduled scan at ${new Date().toISOString()}`);
      scanStatus = { running: true, startedAt: new Date().toISOString(), images };

      Promise.resolve()
        .then(() => scanAll(configs))
        .then((results) => {
          console.log("[cron] Scheduled scan complete");
          return notifyCriticals(results);
        })
        .catch((err) => console.error("[cron] Scheduled scan failed:", err.message))
        .finally(() => {
          scanStatus = { running: false, startedAt: null, images: [] };
        });
    });
    console.log(`Cron scheduled: "${SCAN_CRON}"`);
  } else {
    console.warn(`Invalid SCAN_CRON expression: "${SCAN_CRON}", cron disabled`);
  }

  // Weekly summary
  const WEEKLY_CRON = process.env.WEEKLY_CRON;
  if (WEEKLY_CRON && cron.validate(WEEKLY_CRON)) {
    cron.schedule(WEEKLY_CRON, () => {
      console.log(`[cron] Sending weekly summary at ${new Date().toISOString()}`);
      notifyWeeklySummary();
    });
    console.log(`Weekly summary scheduled: "${WEEKLY_CRON}"`);
  }
});
