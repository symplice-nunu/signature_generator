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
    void shouldSuccessfullyRegisterNewUserWithValidInformation() {
        // Arrange
        User user = new User();
        user.setUsername("testuser");
        user.setPassword("testpassword");
        user.setEmail("test@example.com");
        user.setPhone("1234567890");

        User registeredUser = new User();
        registeredUser.setUsername("testuser");
        registeredUser.setEmail("test@example.com");
        registeredUser.setVerificationToken("testtoken");

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
        assertEquals("testuser", responseBody.get("username"));
        assertEquals("test@example.com", responseBody.get("email"));

        verify(userService).registerUser("testuser", "testpassword", "test@example.com", "1234567890");
        verify(emailService).sendEmail(eq("test@example.com"), eq("Verify Your Email"), contains("http://signaturegenerator.samueldev.com/api/auth/verify?token=testtoken"));
    }

    @Test
    void shouldReturnErrorWhenRegisteringWithExistingEmail() {
        // Arrange
        User user = new User();
        user.setUsername("existinguser");
        user.setPassword("password123");
        user.setEmail("existing@example.com");
        user.setPhone("1234567890");

        when(userService.registerUser(anyString(), anyString(), anyString(), anyString()))
                .thenThrow(new IllegalArgumentException("Email already exists"));

        // Act
        ResponseEntity<?> response = authController.register(user);

        // Assert
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertTrue(response.getBody() instanceof Map);
        Map<String, Object> responseBody = (Map<String, Object>) response.getBody();
        assertFalse((Boolean) responseBody.get("success"));
        assertEquals("Email already exists", responseBody.get("message"));

        verify(userService).registerUser("existinguser", "password123", "existing@example.com", "1234567890");
        verifyNoInteractions(emailService);
    }

    @Test
    void shouldSendVerificationEmailAfterSuccessfulRegistration() {
        // Arrange
        User user = new User();
        user.setUsername("newuser");
        user.setPassword("password123");
        user.setEmail("newuser@example.com");
        user.setPhone("1234567890");

        User registeredUser = new User();
        registeredUser.setUsername("newuser");
        registeredUser.setEmail("newuser@example.com");
        registeredUser.setVerificationToken("verificationtoken123");

        when(userService.registerUser(anyString(), anyString(), anyString(), anyString())).thenReturn(registeredUser);
        doNothing().when(emailService).sendEmail(anyString(), anyString(), anyString());

        // Act
        ResponseEntity<?> response = authController.register(user);

        // Assert
        assertEquals(HttpStatus.OK, response.getStatusCode());
        verify(userService).registerUser("newuser", "password123", "newuser@example.com", "1234567890");
        verify(emailService).sendEmail(
                eq("newuser@example.com"),
                eq("Verify Your Email"),
                contains("http://signaturegenerator.samueldev.com/api/auth/verify?token=verificationtoken123")
        );
    }

    @Test
    void shouldVerifyUserEmailWithValidToken() {
        // Arrange
        String validToken = "validToken123";
        User user = new User();
        user.setVerified(false);
        user.setVerificationToken(validToken);

        when(userService.findByVerificationToken(validToken)).thenReturn(user);
        when(userService.isTokenExpired(user)).thenReturn(false);

        // Act
        ResponseEntity<?> response = authController.verifyEmail(validToken);

        // Assert
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("Email verified successfully!", response.getBody());
        assertTrue(user.isVerified());
        assertNull(user.getVerificationToken());

        verify(userService).findByVerificationToken(validToken);
        verify(userService).isTokenExpired(user);
        verify(userService).saveUser(user);
    }

    @Test
    void shouldReturnErrorWhenVerifyingWithExpiredToken() {
        // Arrange
        String expiredToken = "expiredToken123";
        User user = new User();
        user.setVerified(false);
        user.setVerificationToken(expiredToken);

        when(userService.findByVerificationToken(expiredToken)).thenReturn(user);
        when(userService.isTokenExpired(user)).thenReturn(true);

        // Act
        ResponseEntity<?> response = authController.verifyEmail(expiredToken);

        // Assert
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals("Verification token has expired. Please request a new one.", response.getBody());
        assertFalse(user.isVerified());
        assertNotNull(user.getVerificationToken());

        verify(userService).findByVerificationToken(expiredToken);
        verify(userService).isTokenExpired(user);
        verifyNoMoreInteractions(userService);
    }

    @Test
    void shouldSuccessfullyLoginVerifiedUserWithCorrectCredentials() {
        // Arrange
        User user = new User();
        user.setEmail("test@example.com");
        user.setPassword("correctPassword");

        User loggedInUser = new User();
        loggedInUser.setId(1L);
        loggedInUser.setUsername("testuser");
        loggedInUser.setEmail("test@example.com");
        loggedInUser.setVerified(true);

        when(userService.authenticate("test@example.com", "correctPassword")).thenReturn(true);
        when(userService.findByEmail("test@example.com")).thenReturn(loggedInUser);
        when(jwtService.buildToken("testuser", 1L)).thenReturn("mocked.jwt.token");

        // Act
        ResponseEntity<?> response = authController.login(user);

        // Assert
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertTrue(response.getBody() instanceof Map);
        Map<String, Object> responseBody = (Map<String, Object>) response.getBody();
        assertTrue((Boolean) responseBody.get("success"));
        assertEquals("Login successful", responseBody.get("message"));
        assertEquals("mocked.jwt.token", responseBody.get("token"));
        assertEquals("test@example.com", responseBody.get("email"));
        assertEquals(1L, responseBody.get("userId"));

        verify(userService).authenticate("test@example.com", "correctPassword");
        verify(userService).findByEmail("test@example.com");
        verify(jwtService).buildToken("testuser", 1L);
    }

    @Test
    void shouldReturnErrorWhenLoggingInWithIncorrectPassword() {
        // Arrange
        User user = new User();
        user.setEmail("test@example.com");
        user.setPassword("incorrectPassword");

        when(userService.authenticate("test@example.com", "incorrectPassword")).thenReturn(false);

        // Act
        ResponseEntity<?> response = authController.login(user);

        // Assert
        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        assertTrue(response.getBody() instanceof Map);
        Map<String, Object> responseBody = (Map<String, Object>) response.getBody();
        assertFalse((Boolean) responseBody.get("success"));
        assertEquals("Invalid email or password, or unverified email", responseBody.get("message"));

        verify(userService).authenticate("test@example.com", "incorrectPassword");
        verifyNoMoreInteractions(userService, jwtService);
    }

    @Test
    void shouldReturnErrorWhenLoggingInWithUnverifiedEmail() {
        // Arrange
        User user = new User();
        user.setEmail("unverified@example.com");
        user.setPassword("password123");

        User unverifiedUser = new User();
        unverifiedUser.setId(2L);
        unverifiedUser.setUsername("unverifieduser");
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
    void shouldGenerateAndReturnJwtTokenUponSuccessfulLogin() {
        // Arrange
        User user = new User();
        user.setEmail("test@example.com");
        user.setPassword("correctPassword");

        User loggedInUser = new User();
        loggedInUser.setId(1L);
        loggedInUser.setUsername("testuser");
        loggedInUser.setEmail("test@example.com");
        loggedInUser.setVerified(true);

        when(userService.authenticate("test@example.com", "correctPassword")).thenReturn(true);
        when(userService.findByEmail("test@example.com")).thenReturn(loggedInUser);
        when(jwtService.buildToken("testuser", 1L)).thenReturn("mocked.jwt.token");

        // Act
        ResponseEntity<?> response = authController.login(user);

        // Assert
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertInstanceOf(Map.class, response.getBody());
        Map<String, Object> responseBody = (Map<String, Object>) response.getBody();
        assertTrue((Boolean) responseBody.get("success"));
        assertEquals("Login successful", responseBody.get("message"));
        assertEquals("mocked.jwt.token", responseBody.get("token"));
        assertEquals("test@example.com", responseBody.get("email"));
        assertEquals(1L, responseBody.get("userId"));

        verify(userService).authenticate("test@example.com", "correctPassword");
        verify(userService).findByEmail("test@example.com");
        verify(jwtService).buildToken("testuser", 1L);
    }

    @Test
    void shouldReturnSuccessMessageOnLogout() {
        // Arrange
        HttpServletRequest mockRequest = mock(HttpServletRequest.class);

        // Act
        ResponseEntity<Map<String, Object>> response = authController.logout(mockRequest);

        // Assert
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        Map<String, Object> responseBody = response.getBody();
        assertTrue((Boolean) responseBody.get("success"));
        assertEquals("Logged out successfully. Please delete the JWT token on your end.", responseBody.get("message"));
    }
}
