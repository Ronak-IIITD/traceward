import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;

class ResourceQuery {
    void lookup(HttpServletRequest request, Connection connection) throws SQLException {
        String user = request.getParameter("user");
        try (Statement statement = connection.createStatement()) {
            statement.executeQuery("SELECT id FROM users WHERE name = '" + user + "'");
        }
    }
}
