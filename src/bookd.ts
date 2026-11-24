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

import crypto from "node:crypto";
import { query, queryOne } from "./db.js";

const TOKEN_URL = "https://api.tripleseat.com/oauth2/token";
const AUTHORIZE_URL = "https://login.tripleseat.com/oauth2/authorize";
const API_BASE = "https://api.tripleseat.com/v1";
const TOKEN_ROW = "bookd";

export const BOOKD_SCOPES = ["events:read", "locations:read", "sites:read"].join(" ");

interface TokenResponse {
  access_token: string;
  token_type?: string;
  expires_in?: number;
  refresh_token?: string;
  scope?: string;
}

let cached: { access_token: string; expires_at: number } | null = null;
let refreshing: Promise<string> | null = null;

function credentials() {
  const clientId = process.env.BOOKD_TS_CLIENT_ID;
  const clientSecret = process.env.BOOKD_TS_CLIENT_SECRET;
  if (!clientId || !clientSecret) {
    throw new Error(
      "BOOK'D Reader is not set up yet. Add BOOKD_TS_CLIENT_ID and BOOKD_TS_CLIENT_SECRET in Vercel."
    );
  }
  return { clientId, clientSecret };
}

export function bookdConfigured(): boolean {
  return !!(process.env.BOOKD_TS_CLIENT_ID && process.env.BOOKD_TS_CLIENT_SECRET);
}

export function bookdAuthorizeUrl(redirectUri: string, state: string): string {
  const { clientId } = credentials();
  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: "code",
    scope: BOOKD_SCOPES,
    state,
  });
  return AUTHORIZE_URL + "?" + params.toString();
}

async function tokenRequest(body: Record<string, string>): Promise<TokenResponse> {
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
  const data = JSON.parse(text) as TokenResponse;
  if (!data.access_token) throw new Error("Tripleseat token response had no access token");
  return data;
}

async function saveTokens(tokens: TokenResponse): Promise<void> {
  const expiresAt = new Date(Date.now() + (tokens.expires_in || 7200) * 1000);
  await query(
    `INSERT INTO tripleseat_tokens (id, access_token, refresh_token, expires_at, updated_at)
     VALUES ($1, $2, $3, $4, NOW())
     ON CONFLICT (id) DO UPDATE SET
       access_token = $2, refresh_token = $3, expires_at = $4, updated_at = NOW()`,
    [TOKEN_ROW, tokens.access_token, tokens.refresh_token || null, expiresAt.toISOString()]
  );
  cached = { access_token: tokens.access_token, expires_at: expiresAt.getTime() };
}

export async function bookdExchangeCode(code: string, redirectUri: string): Promise<void> {
  const tokens = await tokenRequest({ grant_type: "authorization_code", code, redirect_uri: redirectUri });
  await saveTokens(tokens);
}

async function refreshFromDb(): Promise<string> {
  const row = await queryOne<{ access_token: string; refresh_token: string | null; expires_at: string }>(
    `SELECT access_token, refresh_token, expires_at FROM tripleseat_tokens WHERE id = $1`,
    [TOKEN_ROW]
  );
  if (!row) throw new Error("BOOK'D Reader has not been authorized yet. Visit /auth/bookd.");

  const expiresAt = new Date(row.expires_at).getTime();
  if (Date.now() < expiresAt - 300_000) {
    cached = { access_token: row.access_token, expires_at: expiresAt };
    return row.access_token;
  }
  if (!row.refresh_token) throw new Error("BOOK'D Reader needs to be authorized again. Visit /auth/bookd.");

  const tokens = await tokenRequest({ grant_type: "refresh_token", refresh_token: row.refresh_token });
  // Rotating refresh tokens: the old one is already dead, so saving is critical.
  try {
    await saveTokens(tokens);
  } catch {
    await saveTokens(tokens);
  }
  return tokens.access_token;
}

export async function bookdAccessToken(): Promise<string> {
  if (cached && Date.now() < cached.expires_at - 300_000) return cached.access_token;
  // One refresh at a time in this instance, so a rotated token is never used twice.
  if (!refreshing) {
    refreshing = refreshFromDb().finally(() => {
      refreshing = null;
    });
  }
  return refreshing;
}

export async function bookdStatus(): Promise<{ configured: boolean; authorized: boolean; updated_at?: string; keys: number }> {
  const row = await queryOne<{ updated_at: string; refresh_token: string | null }>(
    `SELECT updated_at, refresh_token FROM tripleseat_tokens WHERE id = $1`,
    [TOKEN_ROW]
  );
  const keys = await queryOne<{ n: string }>(`SELECT COUNT(*) AS n FROM bookd_feed_keys WHERE revoked_at IS NULL`);
  return {
    configured: bookdConfigured(),
    authorized: !!row?.refresh_token,
    updated_at: row?.updated_at,
    keys: Number(keys?.n || 0),
  };
}

// ── Feed keys ──

function hashKey(key: string): string {
  return crypto.createHash("sha256").update(key).digest("hex");
}

/** Create a new feed key, revoking any older ones. Returns the key once. */
export async function createFeedKey(): Promise<string> {
  const key = "bookd_" + crypto.randomBytes(32).toString("base64url");
  await query(`UPDATE bookd_feed_keys SET revoked_at = NOW() WHERE revoked_at IS NULL`);
  await query(`INSERT INTO bookd_feed_keys (key_hash) VALUES ($1)`, [hashKey(key)]);
  return key;
}

export async function feedKeyValid(key: string | undefined): Promise<boolean> {
  if (!key || !key.startsWith("bookd_") || key.length < 40) return false;
  const row = await queryOne<{ id: string }>(
    `UPDATE bookd_feed_keys SET last_used_at = NOW()
     WHERE key_hash = $1 AND revoked_at IS NULL RETURNING id`,
    [hashKey(key)]
  );
  return !!row;
}

// ── Read-only Tripleseat calls ──

async function bookdGet(endpoint: string, params: Record<string, string> = {}): Promise<any> {
  const url = new URL(`${API_BASE}${endpoint}.json`);
  for (const [k, v] of Object.entries(params)) if (v) url.searchParams.set(k, v);

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
    if (!response.ok) throw new Error(`Tripleseat API error (${response.status}) on ${endpoint}`);
    return JSON.parse(text);
  }
  throw new Error(`Tripleseat API kept refusing ${endpoint}`);
}

export interface FeedEvent {
  id: number;
  name: string;
  status: string;
  start: string;
  end: string;
  rooms: string[];
  guest_count: number | null;
  location_id: number | null;
  updated_at: string | null;
  owner_id: number | null;
  owner: string | null;
}

/** Page through Tripleseat's event search until a page comes back empty. */
export async function searchAllEvents(params: Record<string, string>, maxPages = 40): Promise<any[]> {
  const all: any[] = [];
  const seen = new Set<number>();
  let totalPages: number | undefined;

  for (let page = 1; page <= maxPages; page++) {
    const data = await bookdGet("/events/search", { ...params, page: String(page) });
    const items: any[] = Array.isArray(data) ? data : data?.results || data?.data || [];
    if (typeof data?.total_pages === "number") totalPages = data.total_pages;
    let fresh = 0;
    for (const item of items) {
      const ev = item?.event || item;
      if (ev?.id && !seen.has(ev.id)) {
        seen.add(ev.id);
        all.push(ev);
        fresh++;
      }
    }
    if (items.length === 0 || fresh === 0) break;
    if (totalPages !== undefined && page >= totalPages) break;
  }
  return all;
}

function roomNames(ev: any): string[] | null {
  if (!Array.isArray(ev?.rooms)) return null;
  return ev.rooms.map((r: any) => String(r?.name || "").trim()).filter(Boolean);
}

/** Event owners' names by Tripleseat user id, kept while the server stays warm. */
const ownerNames = new Map<number, string>();

function personName(u: any): string | null {
  if (!u || typeof u !== "object") return null;
  const name = [u.first_name, u.last_name].map((x) => String(x || "").trim()).filter(Boolean).join(" ");
  return name || null;
}

function ownerId(ev: any): number | null {
  const id = Number(ev?.owned_by ?? ev?.owner?.id);
  return Number.isFinite(id) && id > 0 ? id : null;
}

/**
 * Names the owner of each event. BOOK'D Reader may only read events, so a name comes
 * from an event record's owner; for an owner no record here names, one of their events
 * is read in full (once per owner while the server stays warm).
 */
async function nameOwners(events: any[]): Promise<void> {
  for (const ev of events) {
    const id = ownerId(ev);
    const name = personName(ev?.owner);
    if (id && name) ownerNames.set(id, name);
  }
  const missing = new Map<number, number>();
  for (const ev of events) {
    const id = ownerId(ev);
    if (id && !ownerNames.has(id) && !missing.has(id)) missing.set(id, ev.id);
  }
  for (const [id, eventId] of [...missing].slice(0, 20)) {
    try {
      const detail = await bookdGet(`/events/${eventId}`);
      const name = personName((detail?.event || detail)?.owner);
      if (name) ownerNames.set(id, name);
    } catch {
      // the owner stays unnamed; the event still shows
    }
  }
}

function toFeedEvent(ev: any): FeedEvent | null {
  if (!ev || ev.deleted_at) return null;
  const status = String(ev.status || "").toUpperCase();
  if (status === "LOST") return null;
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
    owner: (ownerId(ev) && ownerNames.get(ownerId(ev) as number)) || personName(ev.owner),
  };
}

/**
 * Events for BOOK'D between two dates (MM/DD/YYYY), Lost and deleted events left out.
 * When a search result lacks its rooms or its deleted flag, the full record is read,
 * four at a time to stay under Tripleseat's 10 requests a second.
 */
export async function bookdEvents(from: string, to: string): Promise<FeedEvent[]> {
  const raw = await searchAllEvents({
    event_start_date: from,
    event_end_date: to,
    order: "event_start",
    sort_direction: "asc",
  });

  const ready: any[] = [];
  const needDetail: number[] = [];
  for (const ev of raw) {
    if (ev.deleted_at) continue;
    if (String(ev.status || "").toUpperCase() === "LOST") continue;
    if (roomNames(ev) === null || !("deleted_at" in ev)) needDetail.push(ev.id);
    else ready.push(ev);
  }

  for (let i = 0; i < needDetail.length; i += 4) {
    const batch = await Promise.all(
      needDetail.slice(i, i + 4).map(async (id) => {
        const detail = await bookdGet(`/events/${id}`);
        return detail?.event || detail;
      })
    );
    ready.push(...batch);
    if (i + 4 < needDetail.length) await new Promise((r) => setTimeout(r, 450));
  }

  await nameOwners(ready);

  return ready
    .map(toFeedEvent)
    .filter((e): e is FeedEvent => e !== null)
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

export const GEM_ROOMS = ["Pearl", "Emerald", "Ruby", "Onyx"] as const;

/** "Emerald Room", "the emerald room", "Onyx Studio" -> "Emerald" / "Onyx"; null if not a GEM room. */
export function gemRoom(name: unknown): string | null {
  const s = String(name || "").toLowerCase().replace(/^the\s+/, "").trim();
  for (const g of GEM_ROOMS) {
    const k = g.toLowerCase();
    if (s === k || s === k + " room" || (g === "Onyx" && s === "onyx studio")) return g;
  }
  return null;
}

/** "20261121T120000", "2026-11-21T12:00", "11/21/2026 12:00 PM" -> "20261121T120000" (Pacific wall time). */
export function localStamp(value: unknown): string | null {
  const s = String(value || "").trim();
  let m = s.match(/^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})?$/);
  if (m) return `${m[1]}${m[2]}${m[3]}T${m[4]}${m[5]}${m[6] || "00"}`;
  m = s.match(/^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})(?::(\d{2}))?$/);
  if (m) return `${m[1]}${m[2]}${m[3]}T${m[4]}${m[5]}${m[6] || "00"}`;
  m = s.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})\s+(\d{1,2}):(\d{2})\s*([AaPp])\.?[Mm]\.?$/);
  if (m) {
    let h = Number(m[4]) % 12;
    if (m[6].toLowerCase() === "p") h += 12;
    const pad = (n: number | string) => String(n).padStart(2, "0");
    return `${m[3]}${pad(m[1])}${pad(m[2])}T${pad(h)}${m[5]}00`;
  }
  return null;
}

function stampValid(st: string): boolean {
  const y = Number(st.slice(0, 4)), mo = Number(st.slice(4, 6)), d = Number(st.slice(6, 8));
  const h = Number(st.slice(9, 11)), mi = Number(st.slice(11, 13));
  return y >= 2024 && y <= 2100 && mo >= 1 && mo <= 12 && d >= 1 && d <= 31 && h <= 23 && mi <= 59;
}

function stampToFeedDate(st: string): string {
  return `${st.slice(4, 6)}/${st.slice(6, 8)}/${st.slice(0, 4)}`;
}

function addDays(feedDate: string, n: number): string {
  const [mo, d, y] = feedDate.split("/").map(Number);
  const t = new Date(Date.UTC(y, mo - 1, d + n));
  return `${String(t.getUTCMonth() + 1).padStart(2, "0")}/${String(t.getUTCDate()).padStart(2, "0")}/${t.getUTCFullYear()}`;
}

/** Tripleseat feed time "11/24/2026 06:00 PM" -> "20261124T180000". */
function feedToStamp(s: string): string | null {
  return localStamp(s);
}

function niceTime(st: string): string {
  let h = Number(st.slice(9, 11));
  const mi = st.slice(11, 13);
  const ap = h >= 12 ? "PM" : "AM";
  h = h % 12 || 12;
  return mi === "00" ? `${h} ${ap}` : `${h}:${mi} ${ap}`;
}

function niceDate(st: string): string {
  return `${Number(st.slice(4, 6))}/${Number(st.slice(6, 8))}/${st.slice(0, 4)}`;
}

/** Which GEM rooms a Tripleseat room name occupies (buyouts included), as in BOOK'D's build. */
function tsGemRooms(rooms: string[]): string[] {
  const out = new Set<string>();
  for (const r of rooms) {
    const s = r.toLowerCase().trim();
    if (s === "full buyout" || s === "second floor buyout") GEM_ROOMS.forEach((g) => out.add(g));
    const g = gemRoom(r);
    if (g) out.add(g);
  }
  return [...out];
}

const LIVE_STATUSES = new Set(["DEFINITE", "TENTATIVE", "PROSPECT", "CLOSED"]);

export interface PvBookingInput {
  room: string;
  start: string;
  end: string;
  member?: string;
  guests?: number | string | null;
  email_id: string;
  email_received_at?: string;
  status?: string;
}

export interface PvRow {
  email_id: string;
  room: string;
  start_local: string;
  end_local: string;
  member: string;
  guests: number | null;
  status: string;
  email_received_at: string | null;
  created_at: string;
}

/**
 * Record GEM bookings read from PeopleVine emails. Rows whose email id is already
 * recorded are skipped. Returns what was added and, for new bookings, any
 * Tripleseat event holding the same GEM room at an overlapping time.
 */
export async function recordPvBookings(items: PvBookingInput[]) {
  if (!Array.isArray(items) || items.length === 0) throw new Error("bookings must be a non-empty list");
  if (items.length > 100) throw new Error("At most 100 bookings per call");

  const added: PvRow[] = [];
  const skipped: { email_id: string; reason: string }[] = [];

  for (const it of items) {
    const emailId = String(it?.email_id || "").trim();
    const room = gemRoom(it?.room);
    const start = localStamp(it?.start);
    const end = localStamp(it?.end);
    const status = String(it?.status || "booked").trim().toLowerCase();
    if (!emailId || emailId.length > 512) { skipped.push({ email_id: emailId, reason: "missing email_id" }); continue; }
    if (!room) { skipped.push({ email_id: emailId, reason: "not a GEM room (Pearl, Emerald, Ruby, Onyx)" }); continue; }
    if (!start || !end || !stampValid(start) || !stampValid(end) || end <= start) {
      skipped.push({ email_id: emailId, reason: "start/end not readable (use 11/21/2026 12:00 PM or 20261121T120000)" });
      continue;
    }
    if (status !== "booked" && status !== "cancelled") { skipped.push({ email_id: emailId, reason: "status must be booked or cancelled" }); continue; }
    const member = String(it?.member || "").replace(/[\t\r\n]+/g, " ").trim().slice(0, 120);
    const g = it?.guests === undefined || it?.guests === null || it?.guests === "" ? null : Number(it.guests);
    const guests = g !== null && Number.isFinite(g) && g >= 0 && g < 10000 ? Math.round(g) : null;
    const rec = it?.email_received_at ? new Date(String(it.email_received_at)) : null;
    const received = rec && !isNaN(rec.getTime()) ? rec.toISOString() : null;

    const row = await queryOne<PvRow>(
      `INSERT INTO bookd_pv_bookings (email_id, room, start_local, end_local, member, guests, status, email_received_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       ON CONFLICT (email_id) DO NOTHING
       RETURNING email_id, room, start_local, end_local, member, guests, status, email_received_at, created_at`,
      [emailId, room + " Room", start, end, member, guests, status, received]
    );
    if (row) added.push(row);
    else skipped.push({ email_id: emailId, reason: "already recorded" });
  }

  // Live double-booking check for the new bookings against Tripleseat (read only).
  const double_bookings: any[] = [];
  let tripleseat_checked = true;
  const booked = added.filter((r) => r.status === "booked");
  if (booked.length) {
    try {
      const dates = booked.map((r) => stampToFeedDate(r.start_local)).sort();
      const events = await bookdEvents(dates[0], addDays(dates[dates.length - 1], 2));
      for (const r of booked) {
        const g = gemRoom(r.room)!;
        for (const ev of events) {
          if (!LIVE_STATUSES.has(ev.status)) continue;
          const s = feedToStamp(ev.start), e = feedToStamp(ev.end);
          if (!s || !e) continue;
          if (ev.guest_count === 1 && s.slice(9, 13) === "0800" && e.slice(9, 13) === "0930") continue;
          if (!tsGemRooms(ev.rooms).includes(g)) continue;
          if (!(r.start_local < e && s < r.end_local)) continue;
          double_bookings.push({
            date: niceDate(r.start_local),
            room: g,
            peoplevine: { member: r.member, time: `${niceTime(r.start_local)} to ${niceTime(r.end_local)}` },
            tripleseat: { event: ev.name, time: `${niceTime(s)} to ${niceTime(e)}`, status: ev.status },
          });
        }
      }
    } catch (err: any) {
      tripleseat_checked = false;
      console.error("[BOOK'D] Double-booking check failed:", err.message);
    }
  }

  const total = await queryOne<{ n: string }>(`SELECT COUNT(*) AS n FROM bookd_pv_bookings`);
  return {
    added: added.map((r) => ({ email_id: r.email_id, room: r.room, start: r.start_local, end: r.end_local, member: r.member, status: r.status })),
    skipped,
    double_bookings,
    tripleseat_checked,
    total_recorded: Number(total?.n || 0),
    note: "BOOK'D picks these up at its next hourly refresh (about 22 minutes past the hour).",
  };
}

export async function listPvBookings(): Promise<PvRow[]> {
  return query<PvRow>(
    `SELECT email_id, room, start_local, end_local, member, guests, status, email_received_at, created_at
     FROM bookd_pv_bookings ORDER BY created_at, email_id`
  );
}

export async function saveConflicts(body: any): Promise<number> {
  const list = Array.isArray(body?.conflicts) ? body.conflicts : null;
  if (!list) throw new Error("conflicts list missing");
  if (JSON.stringify(list).length > 200_000) throw new Error("conflicts list too large");
  await query(
    `INSERT INTO bookd_state (key, value, updated_at) VALUES ('conflicts', $1::jsonb, NOW())
     ON CONFLICT (key) DO UPDATE SET value = $1::jsonb, updated_at = NOW()`,
    [JSON.stringify({ conflicts: list })]
  );
  return list.length;
}

export async function bookdStatusForRoutine() {
  const pv = await queryOne<{ n: string; newest: string | null; last_added: string | null }>(
    `SELECT COUNT(*) AS n, MAX(email_received_at) AS newest, MAX(created_at) AS last_added FROM bookd_pv_bookings`
  );
  const st = await queryOne<{ value: any; updated_at: string }>(`SELECT value, updated_at FROM bookd_state WHERE key = 'conflicts'`);
  return {
    peoplevine_bookings_recorded: Number(pv?.n || 0),
    newest_email_received_at: pv?.newest || null,
    last_recorded_at: pv?.last_added || null,
    double_bookings: st?.value?.conflicts || [],
    double_bookings_updated_at: st?.updated_at || null,
    note: "double_bookings is BOOK'D's own list from its last hourly build; first_seen says when BOOK'D first saw each one.",
  };
}
