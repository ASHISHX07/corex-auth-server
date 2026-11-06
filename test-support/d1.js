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

    function prepare(sql) {
        let parameters = [];

        return {
            _sql: sql,

            get _parameters() {
                return parameters;
            },

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
    }

    return {
        prepare,

        async batch(statements) {
            database.exec("BEGIN");

            try {
                const results = statements.map(statement => {
                    if (
                        typeof statement?._sql !== "string" ||
                        !Array.isArray(statement._parameters)
                    ) {
                        throw new TypeError(
                            "Invalid prepared statement in batch."
                        );
                    }

                    const result = database
                        .prepare(statement._sql)
                        .run(...statement._parameters);

                    return {
                        success: true,
                        meta: {
                            changes: Number(result.changes)
                        }
                    };
                });

                database.exec("COMMIT");

                return results;
            } catch (error) {
                database.exec("ROLLBACK");
                throw error;
            }
        },

        close() {
            database.close();
        }
    };
}