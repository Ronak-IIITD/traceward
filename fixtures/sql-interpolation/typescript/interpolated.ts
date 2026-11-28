import { DatabaseSync } from "node:sqlite";

const db: DatabaseSync = new DatabaseSync(":memory:");
const name: string = process.argv[2];
const query: string = `SELECT name FROM sqlite_schema WHERE name = '${name}'`;
db.prepare(query);
