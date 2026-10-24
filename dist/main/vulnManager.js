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
/** How long a downloaded copy of the DB stays fresh before we re-fetch. */
const CACHE_TTL_MS = 24 * 60 * 60 * 1000;
class VulnManager {
    constructor() {
        /** In-memory copy so repeated scans in one session don't re-read/parse the file. */
        this.memo = null;
        // Reuse the ~/.nodevm dir the version manager already owns — no new store needed.
        this.cacheFile = path_1.default.join(os_1.default.homedir(), '.nodevm', 'vuln-cache.json');
    }
    /**
     * Scan a set of version strings against the DB. Never throws: on a network
     * failure with no usable cache it returns {} so the UI simply shows no
     * badges rather than breaking the tab. Absence of a badge means "no known
     * advisory", which is also the honest answer when the scan couldn't run.
     */
    async scan(versions) {
        let db;
        try {
            db = await this._getDb();
        }
        catch (e) {
            console.warn('[vuln] scan skipped — DB unavailable:', String(e));
            return {};
        }
        const map = {};
        for (const ver of versions) {
            const hits = db.filter((e) => this._affects(ver, e));
            if (hits.length > 0) {
                map[ver] = hits.map((e) => ({
                    cve: e.cve ?? [],
                    severity: (e.severity ?? 'unknown').toLowerCase(),
                    overview: e.overview ?? e.description,
                    ref: e.ref,
                }));
            }
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
    /** Fresh-enough cache, else fetch and rewrite it. Falls back to a stale cache
     *  when the network is down; only throws when there is nothing usable at all. */
    async _getDb() {
        if (this.memo)
            return this.memo;
        const cached = this._readCache();
        if (cached && Date.now() - cached.fetchedAt < CACHE_TTL_MS) {
            this.memo = cached.data;
            return cached.data;
        }
        try {
            const data = await this._fetch();
            this._writeCache({ fetchedAt: Date.now(), data });
            this.memo = data;
            return data;
        }
        catch (e) {
            if (cached) {
                // Network failed but we have an older copy — stale beats nothing.
                console.warn('[vuln] using stale cache, refresh failed:', String(e));
                this.memo = cached.data;
                return cached.data;
            }
            throw e;
        }
    }
    _readCache() {
        try {
            const raw = fs_1.default.readFileSync(this.cacheFile, 'utf8');
            const parsed = JSON.parse(raw);
            if (parsed && Array.isArray(parsed.data) && typeof parsed.fetchedAt === 'number') {
                return parsed;
            }
        }
        catch {
            // no cache yet, or unreadable/corrupt
        }
        return null;
    }
    _writeCache(cache) {
        try {
            fs_1.default.mkdirSync(path_1.default.dirname(this.cacheFile), { recursive: true });
            fs_1.default.writeFileSync(this.cacheFile, JSON.stringify(cache), 'utf8');
        }
        catch (e) {
            // A read-only home is non-fatal: the scan still works this session via memo.
            console.warn('[vuln] could not write cache:', String(e));
        }
    }
    /** Download the DB and flatten its numeric-keyed object into an array. */
    _fetch(url = DB_URL) {
        return new Promise((resolve, reject) => {
            https_1.default
                .get(url, { headers: { 'User-Agent': 'nodeversions' } }, (res) => {
                // Follow redirects (GitHub raw occasionally 301s to a CDN host).
                if (res.statusCode === 301 || res.statusCode === 302) {
                    res.resume();
                    this._fetch(res.headers.location).then(resolve).catch(reject);
                    return;
                }
                if (res.statusCode !== 200) {
                    res.resume();
                    reject(new Error(`HTTP ${res.statusCode} fetching vuln DB`));
                    return;
                }
                let data = '';
                res.on('data', (c) => (data += c));
                res.on('end', () => {
                    try {
                        const obj = JSON.parse(data);
                        resolve(Object.values(obj));
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
