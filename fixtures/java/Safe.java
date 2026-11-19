import jakarta.servlet.http.HttpServletRequest;
import java.sql.Connection;
import java.sql.PreparedStatement;

class Safe {
    void find(HttpServletRequest request, Connection connection) throws Exception {
        String id = request.getParameter("id");
        PreparedStatement statement = connection.prepareStatement("SELECT name FROM users WHERE id=?");
        statement.setString(1, id);
        statement.executeQuery();
    }
}
