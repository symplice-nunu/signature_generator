package signature_generator.example.signature_generator.controller;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import signature_generator.example.signature_generator.auth.controller.UserController;
import signature_generator.example.signature_generator.auth.model.User;
import signature_generator.example.signature_generator.auth.service.UserService;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserControllerTest {

    @Mock
    private UserService userService;

    @InjectMocks
    private UserController userController;

    @BeforeEach
    void setUp() {
// This method is now empty, but you can add any additional setup if needed
    }

    @Test
    void shouldSuccessfullyUpdatePhoneNumber() {
// Arrange
        Long userId = 1L;
        Map<String, String> phoneRequest = new HashMap<>();
        phoneRequest.put("phone", "1234567890");

// Mock the userService behavior
        when(userService.updatePhoneNumber(userId, "1234567890")).thenReturn(true);

// Act
        ResponseEntity<?> response = userController.updatePhone(userId, phoneRequest);

// Assert
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertTrue(response.getBody() instanceof Map);
        Map<String, Object> responseBody = (Map<String, Object>) response.getBody();
        assertTrue((Boolean) responseBody.get("success"));
        assertEquals("Phone number updated successfully", responseBody.get("message"));

// Verify that the userService method was called
        verify(userService).updatePhoneNumber(userId, "1234567890");
    }

    @Test
    void shouldReturnBadRequestWhenPhoneNumberIsNotProvided() {
        // Arrange
        Long userId = 1L;
        Map<String, String> phoneRequest = new HashMap<>();
        // Empty phone request

        // Act
        ResponseEntity<?> response = userController.updatePhone(userId, phoneRequest);

        // Assert
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals("Phone number is required", response.getBody());

        // Verify that the userService method was not called
        verifyNoInteractions(userService);
    }

    @Test
    void shouldHandleInvalidUserIdInUpdatePhone() {
        // Arrange
        Long invalidUserId = -1L;
        Map<String, String> phoneRequest = new HashMap<>();
        phoneRequest.put("phone", "1234567890");

        // Mock the userService to throw an IllegalArgumentException
        when(userService.updatePhoneNumber(invalidUserId, "1234567890"))
                .thenThrow(new IllegalArgumentException("Invalid user ID"));

        // Act
        ResponseEntity<?> response = userController.updatePhone(invalidUserId, phoneRequest);

        // Assert
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals("Invalid user ID", response.getBody());

        // Verify that the userService method was called
        verify(userService).updatePhoneNumber(invalidUserId, "1234567890");
    }

    @Test
    void shouldSuccessfullyUpdateCompanyInfo() {
        // Arrange
        Long userId = 1L;
        Map<String, String> companyInfo = new HashMap<>();
        companyInfo.put("companyName", "Acme Corp");
        companyInfo.put("missionStatement", "To be the best");
        companyInfo.put("companyAddress", "123 Main St");
        companyInfo.put("companySite", "www.acme.com");
        companyInfo.put("userTitle", "CEO");

        User updatedUser = new User(); // Assuming you have a User class
        when(userService.updateUserCompanyInfo(userId, "Acme Corp", "To be the best",
                "123 Main St", "www.acme.com", "CEO")).thenReturn(updatedUser);

        // Act
        ResponseEntity<?> response = userController.updateCompanyInfo(userId, companyInfo);

        // Assert
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("Company information updated successfully", response.getBody());

        // Verify that the userService method was called with correct parameters
        verify(userService).updateUserCompanyInfo(userId, "Acme Corp", "To be the best",
                "123 Main St", "www.acme.com", "CEO");
    }

    @Test
    void shouldReturnBadRequestWhenUserIdIsNotFoundInUpdateCompanyInfo() {
        // Arrange
        Long nonExistentUserId = 999L;
        Map<String, String> companyInfo = new HashMap<>();
        companyInfo.put("companyName", "Acme Corp");
        companyInfo.put("missionStatement", "To be the best");
        companyInfo.put("companyAddress", "123 Main St");
        companyInfo.put("companySite", "www.acme.com");
        companyInfo.put("userTitle", "CEO");

        when(userService.updateUserCompanyInfo(nonExistentUserId, "Acme Corp", "To be the best",
                "123 Main St", "www.acme.com", "CEO"))
                .thenThrow(new IllegalArgumentException("User not found"));

        // Act
        ResponseEntity<?> response = userController.updateCompanyInfo(nonExistentUserId, companyInfo);

        // Assert
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals("User not found or invalid data", response.getBody());

        // Verify that the userService method was called with correct parameters
        verify(userService).updateUserCompanyInfo(nonExistentUserId, "Acme Corp", "To be the best",
                "123 Main St", "www.acme.com", "CEO");
    }

    @Test
    void shouldReturnListOfAllUsersWhenAuthenticatedUserHasAdminRole() {
        // Arrange
        User adminUser = new User();
        adminUser.setRole("Admin");
        List<User> allUsers = Arrays.asList(new User(), new User());
        when(userService.getAllUsers()).thenReturn(allUsers);

        // Act
        ResponseEntity<?> response = userController.getAllUsers(adminUser);

        // Assert
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertTrue(response.getBody() instanceof List);
        assertEquals(allUsers, response.getBody());

        // Verify that the userService method was called
        verify(userService).getAllUsers();
    }

    @Test
    void shouldReturnOnlyAuthenticatedUserInfoWhenUserIsNotAdmin() {
        // Arrange
        User regularUser = new User();
        regularUser.setRole("User");

        // Act
        ResponseEntity<?> response = userController.getAllUsers(regularUser);

        // Assert
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertTrue(response.getBody() instanceof User);
        assertEquals(regularUser, response.getBody());

        // Verify that the userService.getAllUsers() method was not called
        verifyNoInteractions(userService);
    }

    @Test
    void shouldReturnUnauthorizedStatusWhenUnauthenticatedUserTriesToAccessUsersEndpoint() {
        // Arrange
        User unauthenticatedUser = null;

        // Act
        ResponseEntity<?> response = userController.getAllUsers(unauthenticatedUser);

        // Assert
        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        assertEquals("Unauthorized: Please log in.", response.getBody());

        // Verify that the userService method was not called
        verifyNoInteractions(userService);
    }

    @Test
    void shouldReturnCorrectUserCountWhenCountUsersEndpointIsCalled() {
        // Arrange
        long expectedUserCount = 10L;
        when(userService.countAllUsers()).thenReturn(expectedUserCount);

        // Act
        ResponseEntity<Map<String, Object>> response = userController.countUsers();

        // Assert
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertTrue((Boolean) response.getBody().get("success"));
        assertEquals(expectedUserCount, response.getBody().get("userCount"));

        // Verify that the userService method was called
        verify(userService).countAllUsers();
    }

    @Test
    void shouldHandleAndReturnAppropriateErrorWhenExceptionOccursInCountUsersEndpoint() {
        // Arrange
        when(userService.countAllUsers()).thenThrow(new RuntimeException("Database error"));

        // Act
        ResponseEntity<Map<String, Object>> response = userController.countUsers();

        // Assert
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertNotNull(response.getBody());
        assertFalse((Boolean) response.getBody().get("success"));
        assertEquals("Error fetching user count", response.getBody().get("message"));

        // Verify that the userService method was called
        verify(userService).countAllUsers();
    }
}
