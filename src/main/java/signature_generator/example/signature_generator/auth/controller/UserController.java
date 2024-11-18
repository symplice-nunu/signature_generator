package signature_generator.example.signature_generator.auth.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import signature_generator.example.signature_generator.auth.model.User;
import signature_generator.example.signature_generator.auth.service.UserService;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Controller
@RequiredArgsConstructor
@RequestMapping("/api/v1")
public class UserController {
    private final UserService userService;

    @PutMapping("/update-phone")
    public ResponseEntity<?> updatePhone(@RequestParam("userId") Long userId, @RequestBody Map<String, String> phoneRequest) {
        String newPhone = phoneRequest.get("phone");

        // Check if phone number is provided
        if (newPhone == null || newPhone.isEmpty()) {
            return ResponseEntity.badRequest().body("Phone number is required");
        }

        try {
            // Call service to update the phone
            userService.updatePhoneNumber(userId, newPhone);

            // Return success response
            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("message", "Phone number updated successfully");
            return ResponseEntity.ok(response);

        } catch (IllegalArgumentException e) {
            // Handle invalid user ID or other exceptions
            return ResponseEntity.badRequest().body(e.getMessage());
        } catch (Exception e) {
            // Handle unexpected errors
            e.printStackTrace();
            return ResponseEntity.status(500).body("Internal Server Error");
        }
    }

    @PutMapping("/update-company-info")
    public ResponseEntity<?> updateCompanyInfo(@RequestParam("userId") Long userId,
                                               @RequestBody Map<String, String> companyInfo) {
        // Get the company info from the request body
        String companyName = companyInfo.get("companyName");
        String missionStatement = companyInfo.get("missionStatement");
        String companyAddress = companyInfo.get("companyAddress");
        String companySite = companyInfo.get("companySite");
        String userTitle = companyInfo.get("userTitle");

        try {
            User updatedUser = userService.updateUserCompanyInfo(userId, companyName, missionStatement,
                    companyAddress, companySite, userTitle);

            return ResponseEntity.ok("Company information updated successfully");

        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body("User not found or invalid data");
        }
    }

    @GetMapping("/users")
    public ResponseEntity<?> getAllUsers(@AuthenticationPrincipal User loggedInUser) {
        if (loggedInUser != null && "Admin".equals(loggedInUser.getRole())) {
            List<User> users = userService.getAllUsers();
            return ResponseEntity.ok(users);
        } else if (loggedInUser != null) {
            return ResponseEntity.ok(loggedInUser);
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Unauthorized: Please log in.");
        }
    }



    @GetMapping("/users/count")
    public ResponseEntity<Map<String, Object>> countUsers() {
        try {
            long userCount = userService.countAllUsers(); // Get the user count
            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("userCount", userCount); // Add user count to response

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("success", false);
            errorResponse.put("message", "Error fetching user count");
            return ResponseEntity.status(500).body(errorResponse);
        }
    }
}
