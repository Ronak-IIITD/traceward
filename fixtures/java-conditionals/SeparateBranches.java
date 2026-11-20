import java.sql.SQLException;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;

class SeparateBranches {
    void lookup(boolean enabled, HttpServletRequest request, Statement statement)
            throws SQLException {
        String name = "guest";
        if (enabled) {
            name = request.getParameter("name");
        } else {
            statement.executeQuery("SELECT id FROM users WHERE name = '" + name + "'");
        }
    }
}
