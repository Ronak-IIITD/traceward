import jakarta.servlet.http.HttpServletRequest;
import java.sql.Statement;

class Vulnerable {
    void find(HttpServletRequest request, Statement statement) throws Exception {
        String id = request.getParameter("id");
        String query = "SELECT name FROM users WHERE id='" + id + "'";
        statement.executeQuery(query);
    }
}
