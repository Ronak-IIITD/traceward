import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import javax.servlet.http.HttpServletRequest;

class BoundResourceQuery {
    void lookup(HttpServletRequest request, Connection connection) throws SQLException {
        String user = request.getParameter("user");
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT id FROM users WHERE name = ?")) {
            statement.setString(1, user);
            statement.executeQuery();
        }
    }
}
