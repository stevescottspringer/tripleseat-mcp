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

  return ready
    .map(toFeedEvent)
    .filter((e): e is FeedEvent => e !== null)
    .sort((a, b) => new Date(a.start).getTime() - new Date(b.start).getTime());
}
