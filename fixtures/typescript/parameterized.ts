import { DatabaseSync } from "node:sqlite";

const db = new DatabaseSync(":memory:");
const name: string = process.argv[2];
const statement = db.prepare("SELECT name FROM sqlite_schema WHERE name = ?");
statement.get(name);
