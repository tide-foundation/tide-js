//
// Tide Protocol - Infrastructure for a TRUE Zero-Trust paradigm
// Copyright (C) 2022 Tide Foundation Ltd
//
// This program is free software and is subject to the terms of
// the Tide Community Open Code License as published by the
// Tide Foundation Limited. You may modify it and redistribute
// it in accordance with and subject to the terms of that License.
// This program is distributed WITHOUT WARRANTY of any kind,
// including without any implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE.
// See the Tide Community Open Code License for more details.
// You should have received a copy of the Tide Community Open
// Code License along with this program.
// If not, see https://tide.org/licenses_tcoc2-0-0-en
//

/**
 * A single recent HTTP request observed by the tide-js {@link ClientBase}
 * pipeline. The raw `url` is captured here verbatim; URL sanitization
 * (e.g. stripping uid query params) is the responsibility of the
 * report-building code that drains the buffer, not this module.
 */
export interface RecentRequestEntry {
    /** ISO-8601 timestamp of when the request completed (success) or threw (failure). */
    timestamp: string;
    /** Raw URL — sanitization happens at report-build time, not here. */
    url: string;
    /** Path-only portion of the URL (best-effort; falls back to raw `url` if `new URL(...)` fails). */
    endpoint: string;
    /** HTTP method, e.g. "GET" / "POST" / "PUT". */
    method: string;
    /** HTTP status code on response, or `null` on pre-response failure (DNS, CORS, abort, timeout, ...). */
    httpStatus: number | null;
    /** Duration in milliseconds, measured via `performance.now()`. */
    durationMs: number;
    /** TideError code if the request failed and threw; `null` on success. */
    code: string | null;
}

/**
 * FIFO bounded ring buffer of the most recent HTTP requests issued via
 * {@link ClientBase}. In-memory only — never persisted to localStorage,
 * sessionStorage, or IndexedDB.
 *
 * Singleton state lives at module scope so any code that imports the class
 * sees the same buffer, regardless of how many client instances exist.
 *
 * Default capacity is 20; callers can override via {@link setCapacity}.
 *
 * The buffer is drained at report-build time (e.g. when constructing a
 * tide-js error report) — sanitization of `url` happens there.
 */
export class RecentRequestsBuffer {
    private static _capacity = 20;
    private static _entries: RecentRequestEntry[] = [];

    /** Append an entry; oldest entries are evicted FIFO when capacity is exceeded. */
    static push(entry: RecentRequestEntry): void {
        // Defensive copy so callers can't mutate buffered entries after the fact.
        RecentRequestsBuffer._entries.push({ ...entry });
        const overflow = RecentRequestsBuffer._entries.length - RecentRequestsBuffer._capacity;
        if (overflow > 0) {
            RecentRequestsBuffer._entries.splice(0, overflow);
        }
    }

    /** Returns the up-to-last-N entries in insertion order (oldest first). */
    static snapshot(): RecentRequestEntry[] {
        // Return a defensive shallow-copy + per-entry copy so callers can't
        // mutate the live buffer.
        return RecentRequestsBuffer._entries.map(e => ({ ...e }));
    }

    /** Empty the buffer. */
    static clear(): void {
        RecentRequestsBuffer._entries = [];
    }

    /**
     * Override the bounded capacity. If `n` is less than the current size,
     * the oldest entries are evicted FIFO to fit.
     */
    static setCapacity(n: number): void {
        if (!Number.isFinite(n) || n < 0) return;
        RecentRequestsBuffer._capacity = Math.floor(n);
        const overflow = RecentRequestsBuffer._entries.length - RecentRequestsBuffer._capacity;
        if (overflow > 0) {
            RecentRequestsBuffer._entries.splice(0, overflow);
        }
    }
}
