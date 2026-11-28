import { DatabaseSync } from "node:sqlite";

const db = new DatabaseSync(":memory:");
const name = process.argv[2];
const query = `SELECT name FROM sqlite_schema WHERE name = '${name}'`;
db.prepare(query);
