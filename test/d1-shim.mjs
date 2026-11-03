// Minimal D1 emulation on node:sqlite so the real service code can be tested offline.
import { DatabaseSync } from "node:sqlite";
import fs from "node:fs";

export function createD1(migrationsDir) {
    const db = new DatabaseSync(":memory:");
    db.exec("PRAGMA foreign_keys = ON");
    for (const f of fs.readdirSync(migrationsDir).sort()) db.exec(fs.readFileSync(`${migrationsDir}/${f}`, "utf8"));

    const exec = (sql, params) => {
        const stmt = db.prepare(sql);
        if (/\breturning\b/i.test(sql) || /^\s*select/i.test(sql)) {
            const rows = stmt.all(...params);
            return { results: rows, success: true, meta: { changes: /^\s*select/i.test(sql) ? 0 : rows.length } };
        }
        const r = stmt.run(...params);
        return { results: [], success: true, meta: { changes: Number(r.changes) } };
    };
    const mk = sql => ({
        _sql: sql, _p: [],
        bind(...p) { this._p = p; return this; },
        async run() { return exec(sql, this._p); },
        async all() { return exec(sql, this._p); },
        async first() { return exec(sql, this._p).results[0] ?? null; }
    });
    return {
        raw: db,
        prepare: mk,
        async batch(stmts) {
            db.exec("BEGIN");
            try { const out = stmts.map(s => exec(s._sql, s._p)); db.exec("COMMIT"); return out; }
            catch (e) { db.exec("ROLLBACK"); throw e; }
        }
    };
}
