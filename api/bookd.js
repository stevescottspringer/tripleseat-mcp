"use strict";
/**
 * BOOK'D Reader — a separate, read-only Tripleseat OAuth app for the
 * BOOK'D room calendar.
 *
 * Why it is separate from the connector's own Tripleseat app:
 * - It asks only for events:read, locations:read and sites:read, so the
 *   calendar can never change anything in Tripleseat.
 * - Its tokens live in their own row (tripleseat_tokens id = 'bookd'), so
 *   re-authorizing one never signs the other out.
 *
 * Tripleseat refresh tokens rotate (the old one dies on every refresh), so
 * the tokens are kept here in the database rather than in GitHub secrets.
 * BOOK'D's daily GitHub Action calls GET /bookd/events with a feed key.
 * The feed key is shown once on the admin page and stored only as a hash.
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.GEM_ROOMS = exports.BOOKD_SCOPES = void 0;
exports.bookdConfigured = bookdConfigured;
exports.bookdAuthorizeUrl = bookdAuthorizeUrl;
exports.bookdExchangeCode = bookdExchangeCode;
exports.bookdAccessToken = bookdAccessToken;
exports.bookdStatus = bookdStatus;
exports.createFeedKey = createFeedKey;
exports.feedKeyValid = feedKeyValid;
exports.searchAllEvents = searchAllEvents;
exports.bookdEvents = bookdEvents;
exports.gemRoom = gemRoom;
exports.localStamp = localStamp;
exports.recordPvBookings = recordPvBookings;
exports.listPvBookings = listPvBookings;
exports.saveConflicts = saveConflicts;
exports.bookdStatusForRoutine = bookdStatusForRoutine;
const node_crypto_1 = __importDefault(require("node:crypto"));
const db_js_1 = require("./db.js");
const TOKEN_URL = "https://api.tripleseat.com/oauth2/token";
const AUTHORIZE_URL = "https://login.tripleseat.com/oauth2/authorize";
const API_BASE = "https://api.tripleseat.com/v1";
const TOKEN_ROW = "bookd";
exports.BOOKD_SCOPES = ["events:read", "locations:read", "sites:read"].join(" ");
let cached = null;
let refreshing = null;
function credentials() {
    const clientId = process.env.BOOKD_TS_CLIENT_ID;
    const clientSecret = process.env.BOOKD_TS_CLIENT_SECRET;
    if (!clientId || !clientSecret) {
        throw new Error("BOOK'D Reader is not set up yet. Add BOOKD_TS_CLIENT_ID and BOOKD_TS_CLIENT_SECRET in Vercel.");
    }
    return { clientId, clientSecret };
}
function bookdConfigured() {
    return !!(process.env.BOOKD_TS_CLIENT_ID && process.env.BOOKD_TS_CLIENT_SECRET);
}
function bookdAuthorizeUrl(redirectUri, state) {
    const { clientId } = credentials();
    const params = new URLSearchParams({
        client_id: clientId,
        redirect_uri: redirectUri,
        response_type: "code",
        scope: exports.BOOKD_SCOPES,
        state,
    });
    return AUTHORIZE_URL + "?" + params.toString();
}
async function tokenRequest(body) {
    const { clientId, clientSecret } = credentials();
    const response = await fetch(TOKEN_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify({ client_id: clientId, client_secret: clientSecret, ...body }),
    });
    const text = await response.text();
    if (!response.ok || text.trimStart().startsWith("<")) {
        // Never echo the response body: it can contain tokens.
        throw new Error("Tripleseat token request failed (" + response.status + ")");
    }
    const data = JSON.parse(text);
    if (!data.access_token)
        throw new Error("Tripleseat token response had no access token");
    return data;
}
async function saveTokens(tokens) {
    const expiresAt = new Date(Date.now() + (tokens.expires_in || 7200) * 1000);
    await (0, db_js_1.query)(`INSERT INTO tripleseat_tokens (id, access_token, refresh_token, expires_at, updated_at)
     VALUES ($1, $2, $3, $4, NOW())
     ON CONFLICT (id) DO UPDATE SET
       access_token = $2, refresh_token = $3, expires_at = $4, updated_at = NOW()`, [TOKEN_ROW, tokens.access_token, tokens.refresh_token || null, expiresAt.toISOString()]);
    cached = { access_token: tokens.access_token, expires_at: expiresAt.getTime() };
}
async function bookdExchangeCode(code, redirectUri) {
    const tokens = await tokenRequest({ grant_type: "authorization_code", code, redirect_uri: redirectUri });
    await saveTokens(tokens);
}
async function refreshFromDb() {
    const row = await (0, db_js_1.queryOne)(`SELECT access_token, refresh_token, expires_at FROM tripleseat_tokens WHERE id = $1`, [TOKEN_ROW]);
    if (!row)
        throw new Error("BOOK'D Reader has not been authorized yet. Visit /auth/bookd.");
    const expiresAt = new Date(row.expires_at).getTime();
    if (Date.now() < expiresAt - 300_000) {
        cached = { access_token: row.access_token, expires_at: expiresAt };
        return row.access_token;
    }
    if (!row.refresh_token)
        throw new Error("BOOK'D Reader needs to be authorized again. Visit /auth/bookd.");
    const tokens = await tokenRequest({ grant_type: "refresh_token", refresh_token: row.refresh_token });
    // Rotating refresh tokens: the old one is already dead, so saving is critical.
    try {
        await saveTokens(tokens);
    }
    catch {
        await saveTokens(tokens);
    }
    return tokens.access_token;
}
async function bookdAccessToken() {
    if (cached && Date.now() < cached.expires_at - 300_000)
        return cached.access_token;
    // One refresh at a time in this instance, so a rotated token is never used twice.
    if (!refreshing) {
        refreshing = refreshFromDb().finally(() => {
            refreshing = null;
        });
    }
    return refreshing;
}
async function bookdStatus() {
    const row = await (0, db_js_1.queryOne)(`SELECT updated_at, refresh_token FROM tripleseat_tokens WHERE id = $1`, [TOKEN_ROW]);
    const keys = await (0, db_js_1.queryOne)(`SELECT COUNT(*) AS n FROM bookd_feed_keys WHERE revoked_at IS NULL`);
    return {
        configured: bookdConfigured(),
        authorized: !!row?.refresh_token,
        updated_at: row?.updated_at,
        keys: Number(keys?.n || 0),
    };
}
// ── Feed keys ──
function hashKey(key) {
    return node_crypto_1.default.createHash("sha256").update(key).digest("hex");
}
/** Create a new feed key, revoking any older ones. Returns the key once. */
async function createFeedKey() {
    const key = "bookd_" + node_crypto_1.default.randomBytes(32).toString("base64url");
    await (0, db_js_1.query)(`UPDATE bookd_feed_keys SET revoked_at = NOW() WHERE revoked_at IS NULL`);
    await (0, db_js_1.query)(`INSERT INTO bookd_feed_keys (key_hash) VALUES ($1)`, [hashKey(key)]);
    return key;
}
async function feedKeyValid(key) {
    if (!key || !key.startsWith("bookd_") || key.length < 40)
        return false;
    const row = await (0, db_js_1.queryOne)(`UPDATE bookd_feed_keys SET last_used_at = NOW()
     WHERE key_hash = $1 AND revoked_at IS NULL RETURNING id`, [hashKey(key)]);
    return !!row;
}
// ── Read-only Tripleseat calls ──
async function bookdGet(endpoint, params = {}) {
    const url = new URL(`${API_BASE}${endpoint}.json`);
    for (const [k, v] of Object.entries(params))
        if (v)
            url.searchParams.set(k, v);
    for (let attempt = 0; attempt < 4; attempt++) {
        const token = await bookdAccessToken();
        const response = await fetch(url.toString(), {
            method: "GET",
            headers: { Authorization: `Bearer ${token}`, Accept: "application/json" },
        });
        if (response.status === 401 && attempt === 0) {
            cached = null;
            continue;
        }
        if (response.status === 429) {
            await new Promise((r) => setTimeout(r, 1000 * (attempt + 1)));
            continue;
        }
        const text = await response.text();
        if (!response.ok)
            throw new Error(`Tripleseat API error (${response.status}) on ${endpoint}`);
        return JSON.parse(text);
    }
    throw new Error(`Tripleseat API kept refusing ${endpoint}`);
}
/** Page through Tripleseat's event search until a page comes back empty. */
async function searchAllEvents(params, maxPages = 40) {
    const all = [];
    const seen = new Set();
    let totalPages;
    for (let page = 1; page <= maxPages; page++) {
        const data = await bookdGet("/events/search", { ...params, page: String(page) });
        const items = Array.isArray(data) ? data : data?.results || data?.data || [];
        if (typeof data?.total_pages === "number")
            totalPages = data.total_pages;
        let fresh = 0;
        for (const item of items) {
            const ev = item?.event || item;
            if (ev?.id && !seen.has(ev.id)) {
                seen.add(ev.id);
                all.push(ev);
                fresh++;
            }
        }
        if (items.length === 0 || fresh === 0)
            break;
        if (totalPages !== undefined && page >= totalPages)
            break;
    }
    return all;
}
function roomNames(ev) {
    if (!Array.isArray(ev?.rooms))
        return null;
    return ev.rooms.map((r) => String(r?.name || "").trim()).filter(Boolean);
}
/** Event owners' names by Tripleseat user id, kept while the server stays warm. */
const ownerNames = new Map();
function personName(u) {
    if (!u || typeof u !== "object")
        return null;
    const name = [u.first_name, u.last_name].map((x) => String(x || "").trim()).filter(Boolean).join(" ");
    return name || null;
}
function ownerId(ev) {
    const id = Number(ev?.owned_by ?? ev?.owner?.id);
    return Number.isFinite(id) && id > 0 ? id : null;
}
/**
 * Names the owner of each event. BOOK'D Reader may only read events, so a name comes
 * from an event record's owner; for an owner no record here names, one of their events
 * is read in full (once per owner while the server stays warm).
 */
async function nameOwners(events) {
    for (const ev of events) {
        const id = ownerId(ev);
        const name = personName(ev?.owner);
        if (id && name)
            ownerNames.set(id, name);
    }
    const missing = new Map();
    for (const ev of events) {
        const id = ownerId(ev);
        if (id && !ownerNames.has(id) && !missing.has(id))
            missing.set(id, ev.id);
    }
    for (const [id, eventId] of [...missing].slice(0, 20)) {
        try {
            const detail = await bookdGet(`/events/${eventId}`);
            const name = personName((detail?.event || detail)?.owner);
            if (name)
                ownerNames.set(id, name);
        }
        catch {
            // the owner stays unnamed; the event still shows
        }
    }
}
function toFeedEvent(ev) {
    if (!ev || ev.deleted_at)
        return null;
    const status = String(ev.status || "").toUpperCase();
    if (status === "LOST")
        return null;
    return {
        id: ev.id,
        name: ev.name,
        status,
        start: ev.event_start,
        end: ev.event_end,
        rooms: roomNames(ev) || [],
        guest_count: ev.guest_count ?? null,
        location_id: ev.location_id ?? null,
        updated_at: ev.updated_at ?? null,
        owner_id: ownerId(ev),
        owner: (ownerId(ev) && ownerNames.get(ownerId(ev))) || personName(ev.owner),
    };
}
/**
 * Events for BOOK'D between two dates (MM/DD/YYYY), Lost and deleted events left out.
 * When a search result lacks its rooms or its deleted flag, the full record is read,
 * four at a time to stay under Tripleseat's 10 requests a second.
 */
async function bookdEvents(from, to) {
    const raw = await searchAllEvents({
        event_start_date: from,
        event_end_date: to,
        order: "event_start",
        sort_direction: "asc",
    });
    const ready = [];
    const needDetail = [];
    for (const ev of raw) {
        if (ev.deleted_at)
            continue;
        if (String(ev.status || "").toUpperCase() === "LOST")
            continue;
        if (roomNames(ev) === null || !("deleted_at" in ev))
            needDetail.push(ev.id);
        else
            ready.push(ev);
    }
    for (let i = 0; i < needDetail.length; i += 4) {
        const batch = await Promise.all(needDetail.slice(i, i + 4).map(async (id) => {
            const detail = await bookdGet(`/events/${id}`);
            return detail?.event || detail;
        }));
        ready.push(...batch);
        if (i + 4 < needDetail.length)
            await new Promise((r) => setTimeout(r, 450));
    }
    await nameOwners(ready);
    return ready
        .map(toFeedEvent)
        .filter((e) => e !== null)
        .sort((a, b) => new Date(a.start).getTime() - new Date(b.start).getTime());
}
// ── PeopleVine GEM bookings from email (for BOOK'D) ──
//
// PeopleVine has no API access yet, so BOOK'D learns about member GEM room
// bookings from PeopleVine's "Room Booking Form" notice emails. An hourly
// Claude routine reads those emails in Outlook and records each booking here
// through the bookd_add_peoplevine_gem_bookings tool. BOOK'D's hourly GitHub
// Action reads them back with GET /bookd/peoplevine (feed key) and posts its
// double-booking list to POST /bookd/conflicts, which bookd_status returns.
// None of this touches Tripleseat or PeopleVine.
exports.GEM_ROOMS = ["Pearl", "Emerald", "Ruby", "Onyx"];
/** "Emerald Room", "the emerald room", "Onyx Studio" -> "Emerald" / "Onyx"; null if not a GEM room. */
function gemRoom(name) {
    const s = String(name || "").toLowerCase().replace(/^the\s+/, "").trim();
    for (const g of exports.GEM_ROOMS) {
        const k = g.toLowerCase();
        if (s === k || s === k + " room" || (g === "Onyx" && s === "onyx studio"))
            return g;
    }
    return null;
}
/** "20261121T120000", "2026-11-21T12:00", "11/21/2026 12:00 PM" -> "20261121T120000" (Pacific wall time). */
function localStamp(value) {
    const s = String(value || "").trim();
    let m = s.match(/^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})?$/);
    if (m)
        return `${m[1]}${m[2]}${m[3]}T${m[4]}${m[5]}${m[6] || "00"}`;
    m = s.match(/^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})(?::(\d{2}))?$/);
    if (m)
        return `${m[1]}${m[2]}${m[3]}T${m[4]}${m[5]}${m[6] || "00"}`;
    m = s.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})\s+(\d{1,2}):(\d{2})\s*([AaPp])\.?[Mm]\.?$/);
    if (m) {
        let h = Number(m[4]) % 12;
        if (m[6].toLowerCase() === "p")
            h += 12;
        const pad = (n) => String(n).padStart(2, "0");
        return `${m[3]}${pad(m[1])}${pad(m[2])}T${pad(h)}${m[5]}00`;
    }
    return null;
}
function stampValid(st) {
    const y = Number(st.slice(0, 4)), mo = Number(st.slice(4, 6)), d = Number(st.slice(6, 8));
    const h = Number(st.slice(9, 11)), mi = Number(st.slice(11, 13));
    return y >= 2024 && y <= 2100 && mo >= 1 && mo <= 12 && d >= 1 && d <= 31 && h <= 23 && mi <= 59;
}
function stampToFeedDate(st) {
    return `${st.slice(4, 6)}/${st.slice(6, 8)}/${st.slice(0, 4)}`;
}
function addDays(feedDate, n) {
    const [mo, d, y] = feedDate.split("/").map(Number);
    const t = new Date(Date.UTC(y, mo - 1, d + n));
    return `${String(t.getUTCMonth() + 1).padStart(2, "0")}/${String(t.getUTCDate()).padStart(2, "0")}/${t.getUTCFullYear()}`;
}
/** Tripleseat feed time "11/24/2026 06:00 PM" -> "20261124T180000". */
function feedToStamp(s) {
    return localStamp(s);
}
function niceTime(st) {
    let h = Number(st.slice(9, 11));
    const mi = st.slice(11, 13);
    const ap = h >= 12 ? "PM" : "AM";
    h = h % 12 || 12;
    return mi === "00" ? `${h} ${ap}` : `${h}:${mi} ${ap}`;
}
function niceDate(st) {
    return `${Number(st.slice(4, 6))}/${Number(st.slice(6, 8))}/${st.slice(0, 4)}`;
}
/** Which GEM rooms a Tripleseat room name occupies (buyouts included), as in BOOK'D's build. */
function tsGemRooms(rooms) {
    const out = new Set();
    for (const r of rooms) {
        const s = r.toLowerCase().trim();
        if (s === "full buyout" || s === "second floor buyout")
            exports.GEM_ROOMS.forEach((g) => out.add(g));
        const g = gemRoom(r);
        if (g)
            out.add(g);
    }
    return [...out];
}
const LIVE_STATUSES = new Set(["DEFINITE", "TENTATIVE", "PROSPECT", "CLOSED"]);
/**
 * Record GEM bookings read from PeopleVine emails. Rows whose email id is already
 * recorded are skipped. Returns what was added and, for new bookings, any
 * Tripleseat event holding the same GEM room at an overlapping time.
 */
async function recordPvBookings(items) {
    if (!Array.isArray(items) || items.length === 0)
        throw new Error("bookings must be a non-empty list");
    if (items.length > 100)
        throw new Error("At most 100 bookings per call");
    const added = [];
    const skipped = [];
    for (const it of items) {
        const emailId = String(it?.email_id || "").trim();
        const room = gemRoom(it?.room);
        const start = localStamp(it?.start);
        const end = localStamp(it?.end);
        const status = String(it?.status || "booked").trim().toLowerCase();
        if (!emailId || emailId.length > 512) {
            skipped.push({ email_id: emailId, reason: "missing email_id" });
            continue;
        }
        if (!room) {
            skipped.push({ email_id: emailId, reason: "not a GEM room (Pearl, Emerald, Ruby, Onyx)" });
            continue;
        }
        if (!start || !end || !stampValid(start) || !stampValid(end) || end <= start) {
            skipped.push({ email_id: emailId, reason: "start/end not readable (use 11/21/2026 12:00 PM or 20261121T120000)" });
            continue;
        }
        if (status !== "booked" && status !== "cancelled") {
            skipped.push({ email_id: emailId, reason: "status must be booked or cancelled" });
            continue;
        }
        const member = String(it?.member || "").replace(/[\t\r\n]+/g, " ").trim().slice(0, 120);
        const g = it?.guests === undefined || it?.guests === null || it?.guests === "" ? null : Number(it.guests);
        const guests = g !== null && Number.isFinite(g) && g >= 0 && g < 10000 ? Math.round(g) : null;
        const rec = it?.email_received_at ? new Date(String(it.email_received_at)) : null;
        const received = rec && !isNaN(rec.getTime()) ? rec.toISOString() : null;
        const row = await (0, db_js_1.queryOne)(`INSERT INTO bookd_pv_bookings (email_id, room, start_local, end_local, member, guests, status, email_received_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       ON CONFLICT (email_id) DO NOTHING
       RETURNING email_id, room, start_local, end_local, member, guests, status, email_received_at, created_at`, [emailId, room + " Room", start, end, member, guests, status, received]);
        if (row)
            added.push(row);
        else
            skipped.push({ email_id: emailId, reason: "already recorded" });
    }
    // Live double-booking check for the new bookings against Tripleseat (read only).
    const double_bookings = [];
    let tripleseat_checked = true;
    const booked = added.filter((r) => r.status === "booked");
    if (booked.length) {
        try {
            const dates = booked.map((r) => stampToFeedDate(r.start_local)).sort();
            const events = await bookdEvents(dates[0], addDays(dates[dates.length - 1], 2));
            for (const r of booked) {
                const g = gemRoom(r.room);
                for (const ev of events) {
                    if (!LIVE_STATUSES.has(ev.status))
                        continue;
                    const s = feedToStamp(ev.start), e = feedToStamp(ev.end);
                    if (!s || !e)
                        continue;
                    if (ev.guest_count === 1 && s.slice(9, 13) === "0800" && e.slice(9, 13) === "0930")
                        continue;
                    if (!tsGemRooms(ev.rooms).includes(g))
                        continue;
                    if (!(r.start_local < e && s < r.end_local))
                        continue;
                    double_bookings.push({
                        date: niceDate(r.start_local),
                        room: g,
                        peoplevine: { member: r.member, time: `${niceTime(r.start_local)} to ${niceTime(r.end_local)}` },
                        tripleseat: { event: ev.name, time: `${niceTime(s)} to ${niceTime(e)}`, status: ev.status },
                    });
                }
            }
        }
        catch (err) {
            tripleseat_checked = false;
            console.error("[BOOK'D] Double-booking check failed:", err.message);
        }
    }
    const total = await (0, db_js_1.queryOne)(`SELECT COUNT(*) AS n FROM bookd_pv_bookings`);
    return {
        added: added.map((r) => ({ email_id: r.email_id, room: r.room, start: r.start_local, end: r.end_local, member: r.member, status: r.status })),
        skipped,
        double_bookings,
        tripleseat_checked,
        total_recorded: Number(total?.n || 0),
        note: "BOOK'D picks these up at its next hourly refresh (about 22 minutes past the hour).",
    };
}
async function listPvBookings() {
    return (0, db_js_1.query)(`SELECT email_id, room, start_local, end_local, member, guests, status, email_received_at, created_at
     FROM bookd_pv_bookings ORDER BY created_at, email_id`);
}
async function saveConflicts(body) {
    const list = Array.isArray(body?.conflicts) ? body.conflicts : null;
    if (!list)
        throw new Error("conflicts list missing");
    if (JSON.stringify(list).length > 200_000)
        throw new Error("conflicts list too large");
    await (0, db_js_1.query)(`INSERT INTO bookd_state (key, value, updated_at) VALUES ('conflicts', $1::jsonb, NOW())
     ON CONFLICT (key) DO UPDATE SET value = $1::jsonb, updated_at = NOW()`, [JSON.stringify({ conflicts: list })]);
    return list.length;
}
async function bookdStatusForRoutine() {
    const pv = await (0, db_js_1.queryOne)(`SELECT COUNT(*) AS n, MAX(email_received_at) AS newest, MAX(created_at) AS last_added FROM bookd_pv_bookings`);
    const st = await (0, db_js_1.queryOne)(`SELECT value, updated_at FROM bookd_state WHERE key = 'conflicts'`);
    return {
        peoplevine_bookings_recorded: Number(pv?.n || 0),
        newest_email_received_at: pv?.newest || null,
        last_recorded_at: pv?.last_added || null,
        double_bookings: st?.value?.conflicts || [],
        double_bookings_updated_at: st?.updated_at || null,
        note: "double_bookings is BOOK'D's own list from its last hourly build; first_seen says when BOOK'D first saw each one.",
    };
}
