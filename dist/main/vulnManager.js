"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.VulnManager = void 0;
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
const https_1 = __importDefault(require("https"));
const os_1 = __importDefault(require("os"));
const semver_1 = __importDefault(require("semver"));
/** The official Node.js core vulnerability database, auto-synced from NVD by the
 *  Node.js Security WG. One JSON object keyed by numeric id per advisory. */
const DB_URL = 'https://raw.githubusercontent.com/nodejs/security-wg/main/vuln/core/index.json';
/** The official Node.js release schedule — `end` dates mark when a major line
 *  stops receiving security support. Used to flag EOL versions, which the CVE DB
 *  above reports as "clean" because it only tracks supported lines. */
const SCHEDULE_URL = 'https://raw.githubusercontent.com/nodejs/Release/main/schedule.json';
/** How long a downloaded copy stays fresh before we re-fetch. */
const CACHE_TTL_MS = 24 * 60 * 60 * 1000;
class VulnManager {
    constructor() {
        /** In-memory copies so repeated scans in one session don't re-read/parse files. */
        this.dbMemo = null;
        this.scheduleMemo = null;
        // Reuse the ~/.nodevm dir the version manager already owns — no new store needed.
        const dir = path_1.default.join(os_1.default.homedir(), '.nodevm');
        this.cacheFile = path_1.default.join(dir, 'vuln-cache.json');
        this.scheduleCacheFile = path_1.default.join(dir, 'eol-cache.json');
    }
    /**
     * Scan version strings for security advisories and end-of-life status. Never
     * throws: both data sources are best-effort, so a network failure with no
     * cache simply yields no badges for that source rather than breaking the UI.
     */
    async scan(versions) {
        const db = await this._getDb().catch((e) => {
            console.warn('[vuln] CVE DB unavailable:', String(e));
            return [];
        });
        const schedule = await this._getSchedule().catch((e) => {
            console.warn('[vuln] EOL schedule unavailable:', String(e));
            return {};
        });
        const map = {};
        for (const ver of versions) {
            const cves = db
                .filter((e) => this._affects(ver, e))
                .map((e) => ({
                kind: 'cve',
                cve: e.cve ?? [],
                severity: (e.severity ?? 'unknown').toLowerCase(),
                overview: e.overview ?? e.description,
                ref: e.ref,
            }));
            const eol = this._eolEntry(ver, schedule);
            const all = eol ? [eol, ...cves] : cves;
            if (all.length > 0)
                map[ver] = all;
        }
        return map;
    }
    /**
     * True when `version` falls in an advisory's `vulnerable` range but not in its
     * `patched` range. `patched` lists the first fixed release of each affected
     * line, so a version at or above its line's fix is safe.
     *
     * [Inference] This mirrors the matching used by the official
     * `is-my-node-vulnerable` package (semver.satisfies on the same fields); it is
     * based on the DB's documented format, not verified against that source line
     * by line. Malformed ranges are treated as "not affected" (fail-safe).
     */
    _affects(version, e) {
        const coerced = semver_1.default.coerce(version.replace(/^v/, ''));
        if (!coerced)
            return false;
        const v = coerced.version;
        try {
            if (!e.vulnerable || !semver_1.default.satisfies(v, e.vulnerable, { includePrerelease: true })) {
                return false;
            }
            if (e.patched && semver_1.default.satisfies(v, e.patched, { includePrerelease: true })) {
                return false;
            }
            return true;
        }
        catch {
            return false;
        }
    }
    /**
     * A synthetic "advisory" when `version`'s major line is past its scheduled
     * end-of-life, or null. This catches the CVE DB's blind spot: the last release
     * of an EOL major (e.g. v8.17.0) shows zero CVEs — not because it is safe, but
     * because the DB stops tracking a line once it is unsupported.
     */
    _eolEntry(version, schedule) {
        const coerced = semver_1.default.coerce(version.replace(/^v/, ''));
        if (!coerced)
            return null;
        const entry = schedule[`v${coerced.major}`];
        if (!entry?.end)
            return null;
        const end = Date.parse(entry.end);
        if (Number.isNaN(end) || Date.now() <= end)
            return null; // still supported
        const name = entry.codename ? ` "${entry.codename}"` : '';
        return {
            kind: 'eol',
            cve: [],
            severity: 'critical',
            overview: `Node ${coerced.major}${name} reached end-of-life on ${entry.end} and no longer ` +
                `receives security updates. Upgrade to a supported release.`,
            ref: 'https://nodejs.org/en/about/previous-releases',
        };
    }
    // ── CVE database ──────────────────────────────────────────────
    async _getDb() {
        if (this.dbMemo)
            return this.dbMemo;
        const cached = this._readCache(this.cacheFile);
        if (cached && Date.now() - cached.fetchedAt < CACHE_TTL_MS) {
            this.dbMemo = cached.data;
            return cached.data;
        }
        try {
            const json = await this._fetch(DB_URL);
            const data = Object.values(json);
            this._writeCache(this.cacheFile, { fetchedAt: Date.now(), data });
            this.dbMemo = data;
            return data;
        }
        catch (e) {
            if (cached) {
                console.warn('[vuln] using stale CVE cache, refresh failed:', String(e));
                this.dbMemo = cached.data;
                return cached.data;
            }
            throw e;
        }
    }
    // ── EOL schedule ──────────────────────────────────────────────
    async _getSchedule() {
        if (this.scheduleMemo)
            return this.scheduleMemo;
        const cached = this._readCache(this.scheduleCacheFile);
        if (cached && Date.now() - cached.fetchedAt < CACHE_TTL_MS) {
            this.scheduleMemo = cached.data;
            return cached.data;
        }
        try {
            const data = (await this._fetch(SCHEDULE_URL));
            this._writeCache(this.scheduleCacheFile, { fetchedAt: Date.now(), data });
            this.scheduleMemo = data;
            return data;
        }
        catch (e) {
            if (cached) {
                console.warn('[vuln] using stale EOL cache, refresh failed:', String(e));
                this.scheduleMemo = cached.data;
                return cached.data;
            }
            throw e;
        }
    }
    // ── Shared cache + fetch ──────────────────────────────────────
    _readCache(file) {
        try {
            const parsed = JSON.parse(fs_1.default.readFileSync(file, 'utf8'));
            if (parsed && typeof parsed.fetchedAt === 'number' && parsed.data != null)
                return parsed;
        }
        catch {
            // no cache yet, or unreadable/corrupt
        }
        return null;
    }
    _writeCache(file, cache) {
        try {
            fs_1.default.mkdirSync(path_1.default.dirname(file), { recursive: true });
            fs_1.default.writeFileSync(file, JSON.stringify(cache), 'utf8');
        }
        catch (e) {
            // A read-only home is non-fatal: the scan still works this session via memo.
            console.warn('[vuln] could not write cache:', String(e));
        }
    }
    /** Download and parse a JSON document, following GitHub's occasional redirects. */
    _fetch(url) {
        return new Promise((resolve, reject) => {
            https_1.default
                .get(url, { headers: { 'User-Agent': 'nodeversions' } }, (res) => {
                if (res.statusCode === 301 || res.statusCode === 302) {
                    res.resume();
                    this._fetch(res.headers.location).then(resolve).catch(reject);
                    return;
                }
                if (res.statusCode !== 200) {
                    res.resume();
                    reject(new Error(`HTTP ${res.statusCode} fetching ${url}`));
                    return;
                }
                let data = '';
                res.on('data', (c) => (data += c));
                res.on('end', () => {
                    try {
                        resolve(JSON.parse(data));
                    }
                    catch (e) {
                        reject(e);
                    }
                });
            })
                .on('error', reject);
        });
    }
}
exports.VulnManager = VulnManager;
