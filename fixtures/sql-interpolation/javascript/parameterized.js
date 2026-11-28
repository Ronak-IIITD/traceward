import { DatabaseSync } from "node:sqlite";

const db = new DatabaseSync(":memory:");
const name = process.argv[2];
const bound = `${name}`;
const statement = db.prepare("SELECT name FROM sqlite_schema WHERE name = ?");
statement.get(bound);
