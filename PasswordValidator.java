import java.util.regex.Matcher;
import java.util.regex.Pattern;

/*
      (?=.*[0-9]): At least one digit (0-9).
      (?=.*[A-Z]): At least one uppercase letter (A-Z).
      (?=.*[@#$%^&+=!]): At least one special character among @#$%^&+=!
      {8,}: Minimum length of 8 characters.

*/
public class PasswordValidator {
    private static final String PASSWORD_PATTERN =
            "^(?=.*[0-9])(?=.*[A-Z])(?=.*[@#$%^&+=!]).{8,}$";

    private static final Pattern pattern = Pattern.compile(PASSWORD_PATTERN);

    public static boolean isPasswordValid(String password) {
        Matcher matcher = pattern.matcher(password);
        return matcher.matches();
    }
}
