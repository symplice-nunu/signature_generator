package signature_generator.example.signature_generator.auth.service;

import signature_generator.example.signature_generator.auth.model.User;
import signature_generator.example.signature_generator.auth.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.UUID;
import java.util.List;

@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;

    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    public User registerUser(String username, String password, String email, String phone) {
        // Check if username already exists
        if (userRepository.findByUsername(username).isPresent()) {
            throw new IllegalArgumentException("Username already exists");
        }

        // Check if email already exists
        if (userRepository.findByEmail(email) != null) {
            throw new IllegalArgumentException("Email already exists");
        }

        // Encode the password
        String encodedPassword = passwordEncoder.encode(password);

        // Generate a verification token
        String verificationToken = UUID.randomUUID().toString();

        // Create a new user
        User user = new User(username, encodedPassword, email, phone, "Staff"); // Default role as Staff
        user.setVerificationToken(verificationToken);
        user.setVerified(false); // The user is not verified initially

        // Set the expiration time for the token (e.g., 24 hours from now)
        user.setTokenExpiryTime(System.currentTimeMillis() + 24 * 60 * 60 * 1000); // 24 hours

        // Save the user to the database
        return userRepository.save(user);
    }

    public User findByVerificationToken(String token) {
        return userRepository.findByVerificationToken(token);
    }

    public boolean isTokenExpired(User user) {
        return System.currentTimeMillis() > user.getTokenExpiryTime();
    }

    public void saveUser(User user) {
        userRepository.save(user);
    }

    public User findByEmail(String email) {
        return userRepository.findByEmail(email);  // This method fetches user by email from the database
    }

    public boolean authenticate(String email, String password) {
        User user = userRepository.findByEmail(email);
        if (user == null || !user.isVerified()) {
            return false;
        }
        return passwordEncoder.matches(password, user.getPassword());
    }

    public boolean updatePhoneNumber(Long userId, String phone) {
        // Log the received userId and phone
        System.out.println("Received request to update phone for user ID: " + userId);

        // Check if user exists
        User user = userRepository.findById(userId).orElse(null);
        if (user == null) {
            throw new IllegalArgumentException("User with ID " + userId + " not found");
        }

        // Update the phone number
        System.out.println("Updating phone for user: " + user.getUsername());
        user.setPhone(phone);

        // Save the updated user
        userRepository.save(user);
        System.out.println("Phone updated successfully for user ID: " + userId);

        return true;
    }
    public User updateUserCompanyInfo(Long userId, String companyName, String missionStatement,
                                      String companyAddress, String companySite, String userTitle) {
        // Find the user by ID
        User user = userRepository.findById(userId).orElse(null);

        if (user == null) {
            throw new IllegalArgumentException("User not found");
        }

        // Update the user's company-related fields
        user.setCompanyName(companyName);
        user.setMissionStatement(missionStatement);
        user.setCompanyAddress(companyAddress);
        user.setCompanySite(companySite);
        user.setUserTitle(userTitle);

        // Save the updated user
        return userRepository.save(user);
    }
    public List<User> getAllUsers() {
        return userRepository.findAll();
    }
    public long countAllUsers() {
        return userRepository.count(); // Count all users in the database
    }
    public User findById(Long userId) {
        return userRepository.findById(userId).orElse(null);
    }

}