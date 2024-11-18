package signature_generator.example.signature_generator.auth.controller;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.MediaType;
import signature_generator.example.signature_generator.auth.model.User;
import signature_generator.example.signature_generator.auth.service.JwtService;
import signature_generator.example.signature_generator.auth.service.UserService;
import signature_generator.example.signature_generator.auth.service.EmailService;
import signature_generator.example.signature_generator.auth.util.JwtUtil;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private UserService userService;

    @Autowired
    private EmailService emailService;

    @Autowired
    private JwtService jwtService;

    @PostMapping("/signup")
    public ResponseEntity<?> register(@RequestBody User user) {
        try {
            // Register the user
            User registeredUser = userService.registerUser(
                    user.getUsername(),
                    user.getPassword(),
                    user.getEmail(),
                    user.getPhone()
            );

            // Generate verification URL
            String verificationUrl = "http://localhost:8080/api/auth/verify?token=" + registeredUser.getVerificationToken();

            // Send verification email
            emailService.sendEmail(
                    registeredUser.getEmail(),
                    "Verify Your Email",
                    "Click the following link to verify your email: " + verificationUrl
            );

            // Prepare success response
            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("message", "User registered successfully. Please verify your email.");
            response.put("username", registeredUser.getUsername());
            response.put("email", registeredUser.getEmail());

            return ResponseEntity.ok(response);
        } catch (IllegalArgumentException e) {
            // Handle registration error
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("success", false);
            errorResponse.put("message", e.getMessage());
            return ResponseEntity.badRequest().body(errorResponse);
        }
    }

    // Email Verification
    @GetMapping("/verify")
    public ResponseEntity<?> verifyEmail(@RequestParam("token") String token) {
        // Fetch user by verification token
        User user = userService.findByVerificationToken(token);

        // If user is not found or token is invalid
        if (user == null) {
            return ResponseEntity.badRequest().body("Invalid verification token");
        }

        // Check if the token has expired
        if (userService.isTokenExpired(user)) {
            return ResponseEntity.badRequest().body("Verification token has expired. Please request a new one.");
        }

        // Verify the user and clear the token
        user.setVerified(true);
        user.setVerificationToken(null);  // Clear the token after verification
        userService.saveUser(user);

        // Send success response
        return ResponseEntity.ok("Email verified successfully!");
    }

    // User Login
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody User user) {
        // Authenticate the user
        boolean authenticated = userService.authenticate(user.getEmail(), user.getPassword());

        // If authentication fails
        if (!authenticated) {
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("success", false);
            errorResponse.put("message", "Invalid email or password, or unverified email");
            return ResponseEntity.status(401).body(errorResponse);
        }

        // Fetch the user entity to retrieve the user ID
        User loggedInUser = userService.findByEmail(user.getEmail());

        // If user is not found after authentication
        if (loggedInUser == null) {
            return ResponseEntity.status(500).body("User not found after authentication");
        }

        // If the user's email is not verified, return an error
        if (!loggedInUser.isVerified()) {
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("success", false);
            errorResponse.put("message", "Please verify your email before logging in.");
            return ResponseEntity.status(401).body(errorResponse);
        }

        // Generate JWT token for the authenticated user
        String token = jwtService.buildToken(loggedInUser.getUsername(), loggedInUser.getId());

        // Build the successful login response
        Map<String, Object> response = new HashMap<>();
        response.put("success", true);
        response.put("message", "Login successful");
        response.put("token", token);  // Include the JWT token in the response
        response.put("email", loggedInUser.getEmail());
        response.put("userId", loggedInUser.getId()); // Include user ID in the response

        return ResponseEntity.ok(response);
    }

    @PostMapping("/logout")
    public ResponseEntity<Map<String, Object>> logout(HttpServletRequest request) {
        // The client is responsible for deleting the token on their end (local storage, cookies, etc.)

        // We can send a message confirming that the user has logged out.
        Map<String, Object> response = new HashMap<>();
        response.put("success", true);
        response.put("message", "Logged out successfully. Please delete the JWT token on your end.");

        // In case you use any session-based storage (e.g., Redis or database), you could also invalidate the session here.

        return ResponseEntity.ok(response);
    }


}