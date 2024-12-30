import java.util.Scanner;

public class LoginModule {

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        System.out.println("Welcome to Login Module!");
        System.out.println("Please enter your username:");
        String username = scanner.nextLine();

        System.out.println("Please enter your password:");
        String password = scanner.nextLine();

        boolean authenticated = authenticate(username, password);

        if (authenticated) {
            System.out.println("Login successful!");
        } else {
            System.out.println("Login failed. Please check your credentials.");
        }

        scanner.close();
    }

    private static boolean authenticate(String username, String password) {
        // Dummy authentication logic - replace with actual authentication mechanism
        // For demonstration purposes, always return true if username and password are not empty
        return !username.isEmpty() && !password.isEmpty();
    }
}
