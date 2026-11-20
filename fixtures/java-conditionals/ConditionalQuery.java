import java.sql.SQLException;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;

class ConditionalQuery {
    void lookup(boolean enabled, HttpServletRequest request, Statement statement)
            throws SQLException {
        if (enabled) {
            String name = request.getParameter("name");
            statement.executeQuery("SELECT id FROM users WHERE name = '" + name + "'");
        }
    }
}
