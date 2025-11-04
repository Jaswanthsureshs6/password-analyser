import java.util.Scanner;
import java.util.regex.Pattern;
import java.io.*;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class PasswordAnalyzer {
    private static final Set<String> LEAKS = new HashSet<>();  

    
    private static void loadLeaks() {
        try (BufferedReader br = new BufferedReader(new FileReader("leaked_passwords.txt"))) {
            String line;
            while ((line = br.readLine()) != null) {
                LEAKS.add(line.trim().toLowerCase());
            }
        } catch (IOException e) {
            System.out.println("Warning: leaked_passwords.txt not found. Skipping leak check.");
        }
    }

    
    private static double calculateEntropy(String password) {
        int length = password.length();
        if (length == 0) return 0;
        
        double entropy = Math.log(length) / Math.log(2); 
        if (Pattern.compile("[A-Z]").matcher(password).find()) entropy += 26;  
        if (Pattern.compile("[a-z]").matcher(password).find()) entropy += 26; 
        if (Pattern.compile("[0-9]").matcher(password).find()) entropy += 10;  
        if (Pattern.compile("[^A-Za-z0-9]").matcher(password).find()) entropy += 32; 
        return entropy * length;  
    }

   
    public static int scorePassword(String password) {
        password = password.toLowerCase();  
        int score = 0;
        int length = password.length();

    
        if (length >= 12) score += 2;
        else if (length >= 8) score += 1;

        
        if (Pattern.compile("[A-Z]").matcher(password).find()) score++;  
        if (Pattern.compile("[a-z]").matcher(password).find()) score++; 
        if (Pattern.compile("[0-9]").matcher(password).find()) score++;
        if (Pattern.compile("[^A-Za-z0-9]").matcher(password).find()) score++;

       
        if (Pattern.compile("(123|abc|qwe|asd)").matcher(password).find()) score -= 1;
        if (password.contains("password") || password.contains("letmein")) score -= 2;

        
        double entropy = calculateEntropy(password);
        if (entropy > 50) score += 1;  

        
        if (LEAKS.contains(password)) {
            System.out.println("ALERT: This password appears in leaked databases!");
            score = Math.max(0, score - 3);  
        }

        return Math.max(0, score);  
    }

    
    public static String getSuggestions(int score, String password) {
        StringBuilder sb = new StringBuilder();
        if (password.length() < 8) sb.append("• Use at least 8 chars (12+ ideal). ");
        if (!Pattern.compile("[A-Z]").matcher(password).find()) sb.append("• Add uppercase. ");
        if (!Pattern.compile("[0-9]").matcher(password).find()) sb.append("• Add numbers. ");
        if (!Pattern.compile("[^A-Za-z0-9]").matcher(password).find()) sb.append("• Add symbols (!@#). ");
        if (score < 3) sb.append("• Avoid common words like 'password'. ");
        if (sb.length() == 0) sb.append("• Looks solid—consider a passphrase for even better security.");
        return sb.toString();
    }

   
    public static void writeReport(String password, int score, String rating, String suggestions) {
        try (PrintWriter pw = new PrintWriter(new FileWriter("password_report.txt", true))) {  
            pw.println("--- Analysis Report ---");
            pw.println("Password: " + password.replaceAll(".", "*") + " (length: " + password.length() + ")");
            pw.println("Rating: " + rating + " (Score: " + score + "/7)");
            pw.println("Suggestions: " + suggestions);
            pw.println("Timestamp: " + java.time.LocalDateTime.now());
            pw.println("========================");
            System.out.println("Report saved to password_report.txt");
        } catch (IOException e) {
            System.out.println("Couldn't save report: " + e.getMessage());
        }
    }

    public static void main(String[] args) {
        loadLeaks(); 
        Scanner scanner = new Scanner(System.in);

        System.out.println("🔒 Password Strength Analyzer v1.0");
        System.out.println("Enter 'quit' to exit.");

        while (true) {
            System.out.print("\nEnter password to analyze: ");
            String input = scanner.nextLine().trim();

            if (input.equalsIgnoreCase("quit")) break;

            if (input.isEmpty()) {
                System.out.println("No password entered. Try again.");
                continue;
            }

            int score = scorePassword(input);
            String rating;
            if (score >= 6) rating = "Strong";
            else if (score >= 4) rating = "Good";
            else if (score >= 2) rating = "Medium";
            else rating = "Weak";

            String suggestions = getSuggestions(score, input);

            System.out.println("\nResults:");
            System.out.println("Rating: " + rating + " (Score: " + score + "/7)");
            System.out.println("Entropy: ~" + String.format("%.0f", calculateEntropy(input)) + " bits (higher = harder to crack)");
            System.out.println("Suggestions: " + suggestions);

            writeReport(input, score, rating, suggestions);
        }

        scanner.close();
        System.out.println("Session over. Check password_report.txt for all analyses!");
    }
}