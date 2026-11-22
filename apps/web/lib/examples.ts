const javaExamples = {
  vulnerable: `import jakarta.servlet.http.HttpServletRequest;
import java.sql.Statement;

class UserRepository {
    void find(HttpServletRequest request, Statement statement) throws Exception {
        String id = request.getParameter("id");
        String query = "SELECT name FROM users WHERE id='" + id + "'";
        statement.executeQuery(query);
    }
}`,
  safe: `import jakarta.servlet.http.HttpServletRequest;
import java.sql.Connection;
import java.sql.PreparedStatement;

class UserRepository {
    void find(HttpServletRequest request, Connection connection) throws Exception {
        String id = request.getParameter("id");
        PreparedStatement statement = connection.prepareStatement(
            "SELECT name FROM users WHERE id=?");
        statement.setString(1, id);
        statement.executeQuery();
    }
}`
};

const pythonExamples = {
  vulnerable: `import sqlite3

def find_table():
    db = sqlite3.connect(":memory:")
    name = input()
    query = "SELECT name FROM sqlite_schema WHERE name = '" + name + "'"
    db.execute(query)`,
  safe: `import sqlite3

def find_table():
    db = sqlite3.connect(":memory:")
    name = input()
    query = "SELECT name FROM sqlite_schema WHERE name = ?"
    db.execute(query, (name,))`
};

function nodeExamples(nameDeclaration: string) {
  const setup = `import { DatabaseSync } from "node:sqlite";

const db = new DatabaseSync(":memory:");
${nameDeclaration}`;
  return {
    vulnerable: `${setup}
const query = "SELECT name FROM sqlite_schema WHERE name = '" + name + "'";
db.prepare(query);`,
    safe: `${setup}
const statement = db.prepare("SELECT name FROM sqlite_schema WHERE name = ?");
statement.get(name);`,
  };
}

export const examples = {
  java: javaExamples,
  python: pythonExamples,
  javascript: nodeExamples("const name = process.argv[2];"),
  typescript: nodeExamples("const name: string = process.argv[2];"),
};
export type Language = keyof typeof examples;
export const languages = Object.keys(examples) as Language[];
export const languageNames = {
  java: "Java",
  python: "Python",
  javascript: "JavaScript",
  typescript: "TypeScript",
};
export const snippetNames = {
  java: "snippet.java",
  python: "snippet.py",
  javascript: "snippet.js",
  typescript: "snippet.ts",
};
