import { DatabaseSync } from "node:sqlite";

const db: DatabaseSync = new DatabaseSync(":memory:");
const name: string = process.argv[2];
const bound: string = `${name}`;
const statement = db.prepare("SELECT name FROM sqlite_schema WHERE name = ?");
statement.get(bound);
