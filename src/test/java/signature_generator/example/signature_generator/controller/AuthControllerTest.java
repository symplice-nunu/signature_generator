package signature_generator.example.signature_generator.controller;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import signature_generator.example.signature_generator.auth.controller.AuthController;
import signature_generator.example.signature_generator.auth.model.User;
import signature_generator.example.signature_generator.auth.service.EmailService;
import signature_generator.example.signature_generator.auth.service.JwtService;
import signature_generator.example.signature_generator.auth.service.UserService;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class AuthControllerTest {
    @Mock
    private UserService userService;

    @Mock
    private EmailService emailService;

    @Mock
    private JwtService jwtService;

    @InjectMocks
    private AuthController authController;

    @Test
    public void testRegisterSuccess() {
        // Arrange
        User user = new User();
        user.setUsername("testuser");
        user.setPassword("password123");
        user.setEmail("testuser@example.com");
        user.setPhone("1234567890");

        User registeredUser = new User();
        registeredUser.setUsername("testuser@example.com");
        registeredUser.setEmail("testuser@example.com");
        registeredUser.setVerificationToken("abc123");

        when(userService.registerUser(anyString(), anyString(), anyString(), anyString())).thenReturn(registeredUser);
        doNothing().when(emailService).sendEmail(anyString(), anyString(), anyString());

        // Act
        ResponseEntity<?> response = authController.register(user);

        // Assert
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertTrue(response.getBody() instanceof Map);
        Map<String, Object> responseBody = (Map<String, Object>) response.getBody();
        assertTrue((Boolean) responseBody.get("success"));
        assertEquals("User registered successfully. Please verify your email.", responseBody.get("message"));
        assertEquals("testuser@example.com", responseBody.get("username"));
        assertEquals("testuser@example.com", responseBody.get("email"));

        verify(userService).registerUser("testuser@example.com", "password123", "testuser@example.com", "1234567890");
        verify(emailService).sendEmail(eq("testuser@example.com"), eq("Verify Your Email"), contains("http://signaturegenerator.samueldev.com/api/auth/verify?token=abc123"));
    }

    @Test
    public void testRegisterWithInvalidUserDetails() {
        // Arrange
        User user = new User();
        user.setUsername("");
        user.setPassword("");
        user.setEmail("invalid-email");
        user.setPhone("");

        when(userService.registerUser(anyString(), anyString(), anyString(), anyString()))
                .thenThrow(new IllegalArgumentException("Invalid user details"));

        // Act
        ResponseEntity<?> response = authController.register(user);

        // Assert
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertTrue(response.getBody() instanceof Map);
        Map<String, Object> responseBody = (Map<String, Object>) response.getBody();
        assertFalse((Boolean) responseBody.get("success"));
        assertEquals("Invalid user details", responseBody.get("message"));

        verify(userService).registerUser("invalid-email", "", "invalid-email", "");
        verifyNoInteractions(emailService);
    }

    @Test
    public void testVerifyEmailSuccess() {
        // Arrange
        String token = "validToken123";
        User user = new User();
        user.setVerified(false);
        user.setVerificationToken(token);

        when(userService.findByVerificationToken(token)).thenReturn(user);
        when(userService.isTokenExpired(user)).thenReturn(false);

        // Act
        ResponseEntity<?> response = authController.verifyEmail(token);

        // Assert
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("Email verified successfully!", response.getBody());
        assertTrue(user.isVerified());
        assertNull(user.getVerificationToken());

        verify(userService).findByVerificationToken(token);
        verify(userService).isTokenExpired(user);
        verify(userService).saveUser(user);
    }

    @Test
    public void testVerifyEmailWithInvalidOrExpiredToken() {
        // Arrange
        String invalidToken = "invalidToken123";
        when(userService.findByVerificationToken(invalidToken)).thenReturn(null);

        String expiredToken = "expiredToken456";
        User userWithExpiredToken = new User();
        when(userService.findByVerificationToken(expiredToken)).thenReturn(userWithExpiredToken);
        when(userService.isTokenExpired(userWithExpiredToken)).thenReturn(true);

        // Act & Assert for invalid token
        ResponseEntity<?> responseInvalid = authController.verifyEmail(invalidToken);
        assertEquals(HttpStatus.BAD_REQUEST, responseInvalid.getStatusCode());
        assertEquals("Invalid verification token", responseInvalid.getBody());

        // Act & Assert for expired token
        ResponseEntity<?> responseExpired = authController.verifyEmail(expiredToken);
        assertEquals(HttpStatus.BAD_REQUEST, responseExpired.getStatusCode());
        assertEquals("Verification token has expired. Please request a new one.", responseExpired.getBody());

        // Verify
        verify(userService).findByVerificationToken(invalidToken);
        verify(userService).findByVerificationToken(expiredToken);
        verify(userService).isTokenExpired(userWithExpiredToken);
        verifyNoMoreInteractions(userService);
    }

    @Test
    public void testLoginSuccess() {
        // Arrange
        User user = new User();
        user.setEmail("test@example.com");
        user.setPassword("password123");

        User loggedInUser = new User();
        loggedInUser.setId(1L);
        loggedInUser.setUsername("testuser");
        loggedInUser.setEmail("test@example.com");
        loggedInUser.setVerified(true);

        when(userService.authenticate("test@example.com", "password123")).thenReturn(true);
        when(userService.findByEmail("test@example.com")).thenReturn(loggedInUser);
        when(jwtService.buildToken("test@example.com", 1L)).thenReturn("jwt.token.here");

        // Act
        ResponseEntity<?> response = authController.login(user);

        // Assert
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertTrue(response.getBody() instanceof Map);
        Map<String, Object> responseBody = (Map<String, Object>) response.getBody();
        assertTrue((Boolean) responseBody.get("success"));
        assertEquals("Login successful", responseBody.get("message"));
        assertEquals("jwt.token.here", responseBody.get("token"));
        assertEquals("test@example.com", responseBody.get("email"));
        assertEquals(1L, responseBody.get("userId"));

        verify(userService).authenticate("test@example.com", "password123");
        verify(userService).findByEmail("test@example.com");
        verify(jwtService).buildToken("test@example.com", 1L);
    }

    @Test
    public void testLoginWithInvalidCredentials() {
        // Arrange
        User user = new User();
        user.setEmail("invalid@example.com");
        user.setPassword("wrongpassword");

        when(userService.authenticate("invalid@example.com", "wrongpassword")).thenReturn(false);

        // Act
        ResponseEntity<?> response = authController.login(user);

        // Assert
        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        assertTrue(response.getBody() instanceof Map);
        Map<String, Object> responseBody = (Map<String, Object>) response.getBody();
        assertFalse((Boolean) responseBody.get("success"));
        assertEquals("Invalid email or password, or unverified email", responseBody.get("message"));

        verify(userService).authenticate("invalid@example.com", "wrongpassword");
        verifyNoMoreInteractions(userService);
        verifyNoInteractions(jwtService);
    }

    @Test
    public void testLoginWithUnverifiedEmail() {
        // Arrange
        User user = new User();
        user.setEmail("unverified@example.com");
        user.setPassword("password123");

        User unverifiedUser = new User();
        unverifiedUser.setId(2L);
        unverifiedUser.setUsername("unverified");
        unverifiedUser.setEmail("unverified@example.com");
        unverifiedUser.setVerified(false);

        when(userService.authenticate("unverified@example.com", "password123")).thenReturn(true);
        when(userService.findByEmail("unverified@example.com")).thenReturn(unverifiedUser);

        // Act
        ResponseEntity<?> response = authController.login(user);

        // Assert
        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        assertTrue(response.getBody() instanceof Map);
        Map<String, Object> responseBody = (Map<String, Object>) response.getBody();
        assertFalse((Boolean) responseBody.get("success"));
        assertEquals("Please verify your email before logging in.", responseBody.get("message"));

        verify(userService).authenticate("unverified@example.com", "password123");
        verify(userService).findByEmail("unverified@example.com");
        verifyNoInteractions(jwtService);
    }

    @Test
    public void testLoginWithUserNotFoundAfterAuthentication() {
        // Arrange
        User user = new User();
        user.setEmail("test@example.com");
        user.setPassword("password123");

        when(userService.authenticate("test@example.com", "password123")).thenReturn(true);
        when(userService.findByEmail("test@example.com")).thenReturn(null);

        // Act
        ResponseEntity<?> response = authController.login(user);

        // Assert
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertEquals("User not found after authentication", response.getBody());

        verify(userService).authenticate("test@example.com", "password123");
        verify(userService).findByEmail("test@example.com");
        verifyNoMoreInteractions(userService);
        verifyNoInteractions(jwtService);
    }

    @Test
    public void testLogoutSuccess() {
        // Arrange
        HttpServletRequest mockRequest = mock(HttpServletRequest.class);

        // Act
        ResponseEntity<Map<String, Object>> response = authController.logout(mockRequest);

        // Assert
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertTrue(response.getBody() instanceof Map);
        Map<String, Object> responseBody = response.getBody();
        assertTrue((Boolean) responseBody.get("success"));
        assertEquals("Logged out successfully. Please delete the JWT token on your end.", responseBody.get("message"));

        // Verify that no interactions were made with the mocked request
        verifyNoInteractions(mockRequest);
    }

    @Test
    public void testRegisterWithEmailSendingFailure() {
        // Arrange
        User user = new User();
        user.setUsername("testuser");
        user.setPassword("password123");
        user.setEmail("testuser@example.com");
        user.setPhone("1234567890");

        User registeredUser = new User();
        registeredUser.setUsername("testuser@example.com");
        registeredUser.setEmail("testuser@example.com");
        registeredUser.setVerificationToken("abc123");

        when(userService.registerUser(anyString(), anyString(), anyString(), anyString())).thenReturn(registeredUser);
        doThrow(new RuntimeException("Email sending failed")).when(emailService).sendEmail(anyString(), anyString(), anyString());

        // Act and Assert
        Exception exception = assertThrows(RuntimeException.class, () -> {
            authController.register(user);
        });

        assertEquals("Email sending failed", exception.getMessage());
        assertEquals(RuntimeException.class, exception.getClass());

        verify(userService).registerUser("testuser@example.com", "password123", "testuser@example.com", "1234567890");
        verify(emailService).sendEmail(eq("testuser@example.com"), eq("Verify Your Email"), contains("http://signaturegenerator.samueldev.com/api/auth/verify?token=abc123"));
    }
}
