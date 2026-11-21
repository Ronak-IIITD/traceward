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

export const examples = {java: javaExamples, python: pythonExamples};
export type Language = keyof typeof examples;
export const languageNames = {java: "Java", python: "Python"};
