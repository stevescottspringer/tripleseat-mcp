/**
 * Read-only access to Tripleseat Notes (shown in Tripleseat as Discussions).
 *
 * GET /v1/{parent}/{id}/notes for events, leads, bookings, accounts and
 * contacts (needs the notes:read scope). No write calls live here.
 * Each note's created_by user ID is turned into a name via /users.
 */

import { tripleseatGet } from "./tripleseat.js";

export const NOTE_PARENTS = ["event", "lead", "booking", "account", "contact"] as const;
export type NoteParent = (typeof NOTE_PARENTS)[number];

const PARENT_PATH: Record<NoteParent, string> = {
  event: "events",
  lead: "leads",
  booking: "bookings",
  account: "accounts",
  contact: "contacts",
};

const PER_PAGE = 50;
const MAX_PAGES = 10;
const MAX_BODY_CHARS = 4000;

// ── User names (cached for 30 minutes per warm instance) ──
let userCache: { at: number; names: Map<number, string> } | null = null;

function listOf(data: any, ...keys: string[]): any[] {
  if (Array.isArray(data)) return data;
  for (const k of keys) {
    if (Array.isArray(data?.[k])) return data[k];
  }
  return [];
}

function unwrap(item: any, key: string): any {
  return item && typeof item === "object" && item[key] && typeof item[key] === "object" ? item[key] : item;
}

async function userNames(): Promise<Map<number, string>> {
  if (userCache && Date.now() - userCache.at < 30 * 60 * 1000) return userCache.names;
  const names = new Map<number, string>();
  try {
    const { data } = await tripleseatGet("/users");
    for (const raw of listOf(data, "results", "users", "data")) {
      const u = unwrap(raw, "user");
      const id = Number(u?.id);
      if (!id) continue;
      const full = [u.first_name, u.last_name].filter(Boolean).join(" ").trim();
      const name = full || u.name || u.full_name || u.email || "";
      if (name) names.set(id, name);
    }
  } catch {
    // Names are a convenience; notes still come back with the user ID.
  }
  userCache = { at: Date.now(), names };
  return names;
}

/** Plain text from a note body that may hold HTML. */
export function noteText(body: unknown): string {
  if (typeof body !== "string") return "";
  let t = body
    .replace(/<\s*br\s*\/?>/gi, "\n")
    .replace(/<\/\s*(p|div|li|tr|h[1-6])\s*>/gi, "\n")
    .replace(/<li[^>]*>/gi, "- ")
    .replace(/<[^>]+>/g, "")
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;|&apos;/g, "'")
    .replace(/[ \t]+\n/g, "\n")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
  if (t.length > MAX_BODY_CHARS) t = t.slice(0, MAX_BODY_CHARS) + " [note cut at 4000 characters]";
  return t;
}

export interface NoteOut {
  id: number;
  created_at: string | null;
  author: string | null;
  author_user_id: number | null;
  updated_at?: string;
  updated_by?: string | null;
  text: string;
}

/**
 * List the notes (Discussions) on one Tripleseat record, newest first.
 */
export async function listNotes(
  parent: NoteParent,
  id: string,
  limit = 20
): Promise<{ parent: string; id: string; total: number; shown: number; notes: NoteOut[] }> {
  if (!NOTE_PARENTS.includes(parent)) {
    throw new Error(`parent_type must be one of: ${NOTE_PARENTS.join(", ")}`);
  }
  const cleanId = String(id ?? "").trim();
  if (!/^\d+$/.test(cleanId)) throw new Error("record_id must be a numeric Tripleseat ID");

  const raw: any[] = [];
  const seen = new Set<number>();
  for (let page = 1; page <= MAX_PAGES; page++) {
    const { data } = await tripleseatGet(`/${PARENT_PATH[parent]}/${cleanId}/notes`, {
      page: String(page),
      per_page: String(PER_PAGE),
    });
    const items = listOf(data, "results", "notes", "data");
    let fresh = 0;
    for (const it of items) {
      const n = unwrap(it, "note");
      const nid = Number(n?.id);
      if (nid && seen.has(nid)) continue;
      if (nid) seen.add(nid);
      raw.push(n);
      fresh++;
    }
    const totalPages = (data as any)?.total_pages;
    if (items.length < PER_PAGE || fresh === 0 || (typeof totalPages === "number" && page >= totalPages)) break;
  }

  const names = await userNames();
  const nameOf = (uid: any): string | null => {
    const n = Number(uid);
    if (!n) return null;
    return names.get(n) ?? null;
  };

  const notes: NoteOut[] = raw.map((n) => {
    const createdBy = Number(n?.created_by ?? n?.user_id ?? n?.user?.id) || null;
    const out: NoteOut = {
      id: Number(n?.id),
      created_at: n?.created_at ?? null,
      author: nameOf(createdBy) ?? (n?.user?.name || null),
      author_user_id: createdBy,
      text: noteText(n?.body ?? n?.text ?? n?.note ?? ""),
    };
    if (n?.updated_at && n.updated_at !== n.created_at) {
      out.updated_at = n.updated_at;
      if (n.updated_by && Number(n.updated_by) !== createdBy) out.updated_by = nameOf(n.updated_by);
    }
    return out;
  });

  notes.sort((a, b) => new Date(b.created_at || 0).getTime() - new Date(a.created_at || 0).getTime());
  const cap = Math.max(1, Math.min(Number(limit) || 20, 100));
  const shown = notes.slice(0, cap);
  return { parent, id: cleanId, total: notes.length, shown: shown.length, notes: shown };
}
