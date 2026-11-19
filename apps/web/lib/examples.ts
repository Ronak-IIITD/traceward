export const examples = {
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
