import { DatabaseSync } from "node:sqlite";
import fs from "node:fs";
import path from "node:path";

export function createD1(migrationsDirectory) {
    const database = new DatabaseSync(":memory:");

    database.exec("PRAGMA foreign_keys = ON");

    const migrations = fs.readdirSync(migrationsDirectory)
        .filter(file => file.endsWith(".sql"))
        .sort();

    for (const migration of migrations) {
        const sql = fs.readFileSync(
            path.join(migrationsDirectory, migration),
            "utf8"
        );

        database.exec(sql);
    }

    return {
        prepare(sql) {
            let parameters = [];

            return {
                bind(...values) {
                    parameters = values;
                    return this;
                },

                async run() {
                    const result = database
                        .prepare(sql)
                        .run(...parameters);

                    return {
                        success: true,
                        meta: {
                            changes: Number(result.changes)
                        }
                    };
                },

                async first() {
                    return database
                        .prepare(sql)
                        .get(...parameters) ?? null;
                },

                async all() {
                    return {
                        results: database
                            .prepare(sql)
                            .all(...parameters)
                    };
                }
            };
        },

        close() {
            database.close();
        }
    };
}