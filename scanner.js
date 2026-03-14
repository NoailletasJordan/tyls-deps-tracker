const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const RESULTS_DIR = path.join(__dirname, "results");

function ensureResultsDir() {
  if (!fs.existsSync(RESULTS_DIR)) {
    fs.mkdirSync(RESULTS_DIR, { recursive: true });
  }
}

function sanitizeImageName(image) {
  return image.replace(/[/:@]/g, "_");
}

function scanImage(image) {
  const now = new Date();
  const date = now.toISOString().split("T")[0]; // YYYY-MM-DD
  const time = now.toISOString().split("T")[1].replace(/[:.]/g, "-");
  const sanitizedName = sanitizeImageName(image);

  // Store in per-image subdirectories: results/<image>/<date>_<time>.json
  const imageDir = path.join(RESULTS_DIR, sanitizedName);
  if (!fs.existsSync(imageDir)) {
    fs.mkdirSync(imageDir, { recursive: true });
  }

  const outputFile = path.join(imageDir, `${date}_${time}.json`);

  console.log(`Scanning image: ${image}`);

  try {
    execSync(
      `trivy image --format json --output "${outputFile}" --severity CRITICAL,HIGH,MEDIUM "${image}"`,
      { stdio: "inherit", timeout: 300_000 }
    );

    const raw = JSON.parse(fs.readFileSync(outputFile, "utf-8"));
    const summary = summarize(raw);

    // Write a metadata wrapper so we can read it back with context
    const wrapped = { image, timestamp: now.toISOString(), summary, trivy: raw };
    fs.writeFileSync(outputFile, JSON.stringify(wrapped, null, 2));

    return { image, timestamp: now.toISOString(), summary, raw };
  } catch (err) {
    return { image, timestamp: now.toISOString(), error: err.message };
  }
}

function summarize(trivyOutput) {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0 };

  const results = trivyOutput.Results || [];
  for (const target of results) {
    for (const vuln of target.Vulnerabilities || []) {
      const sev = vuln.Severity;
      if (sev in counts) counts[sev]++;
    }
  }

  return counts;
}

function registryLogin(url, user, pass) {
  if (!url || !user || !pass) return;

  try {
    execSync(
      `trivy registry login --username "${user}" --password "${pass}" "${url}"`,
      { stdio: "inherit" }
    );
    console.log(`Logged in to ${url}`);
  } catch (err) {
    console.error(`Registry login failed: ${err.message}`);
  }
}

function scanAll(imageConfigs) {
  ensureResultsDir();
  return imageConfigs.map(({ image, registryUrl, registryUser, registryPass }) => {
    registryLogin(registryUrl, registryUser, registryPass);
    return scanImage(image.trim());
  }).filter(Boolean);
}

/**
 * List all scanned images (subdirectory names in results/)
 */
function getImages() {
  ensureResultsDir();
  const entries = fs.readdirSync(RESULTS_DIR, { withFileTypes: true });
  return entries.filter((e) => e.isDirectory()).map((e) => e.name);
}

/**
 * Get all scan history for a specific image, sorted newest first.
 * Returns summary-level data (no full vulnerability list) to keep responses light.
 */
function getHistory(imageDirName) {
  const imageDir = path.join(RESULTS_DIR, imageDirName);
  if (!fs.existsSync(imageDir)) return [];

  const files = fs
    .readdirSync(imageDir)
    .filter((f) => f.endsWith(".json"))
    .sort()
    .reverse();

  return files.map((file) => {
    try {
      const data = JSON.parse(
        fs.readFileSync(path.join(imageDir, file), "utf-8")
      );
      return {
        file,
        date: file.replace(".json", "").split("_").slice(0, 3).join("-"),
        image: data.image || imageDirName,
        timestamp: data.timestamp,
        summary: data.summary || summarize(data.trivy || data),
      };
    } catch {
      return { file, error: "Failed to parse" };
    }
  });
}

/**
 * Get full scan detail for a specific scan file.
 */
function getScanDetail(imageDirName, file) {
  const filePath = path.join(RESULTS_DIR, imageDirName, file);
  if (!fs.existsSync(filePath)) return null;

  const data = JSON.parse(fs.readFileSync(filePath, "utf-8"));
  const trivyData = data.trivy || data;

  return {
    image: data.image || imageDirName,
    timestamp: data.timestamp,
    summary: data.summary || summarize(trivyData),
    raw: trivyData,
  };
}

/**
 * Get the latest scan result for each image.
 */
function getLatestResults() {
  const images = getImages();

  return images.map((imgDir) => {
    const history = getHistory(imgDir);
    if (history.length === 0) return { image: imgDir, error: "No scans" };

    const latest = history[0];
    // Load full detail for latest
    return getScanDetail(imgDir, latest.file) || latest;
  });
}

module.exports = {
  scanAll,
  scanImage,
  getLatestResults,
  getImages,
  getHistory,
  getScanDetail,
};
