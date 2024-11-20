package signature_generator.example.signature_generator.service;

import lombok.RequiredArgsConstructor;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;
import signature_generator.example.signature_generator.auth.model.User;
import signature_generator.example.signature_generator.auth.repository.UserRepository;
import signature_generator.example.signature_generator.auth.service.UserService;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class UserServiceTest {
    @Test
    public void testRegisterUserWithExistingUsername() {
        // Arrange
        UserRepository userRepository = mock(UserRepository.class);
        UserService userService = new UserService();
        ReflectionTestUtils.setField(userService, "userRepository", userRepository);

        String existingUsername = "existingUser";
        String password = "password123";
        String email = "newuser@example.com";
        String phone = "1234567890";

        when(userRepository.findByUsername(existingUsername)).thenReturn(Optional.of(new User()));

        // Act & Assert
        assertThrows(IllegalArgumentException.class, () -> {
            userService.registerUser(existingUsername, password, email, phone);
        });

        verify(userRepository, times(1)).findByUsername(existingUsername);
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    public void testRegisterUserWithExistingEmail() {
        // Arrange
        UserRepository userRepository = mock(UserRepository.class);
        UserService userService = new UserService();
        ReflectionTestUtils.setField(userService, "userRepository", userRepository);

        String username = "newUser";
        String password = "password123";
        String existingEmail = "existing@example.com";
        String phone = "1234567890";

        when(userRepository.findByEmail(existingEmail)).thenReturn(new User());

        // Act & Assert
        assertThrows(IllegalArgumentException.class, () -> {
            userService.registerUser(username, password, existingEmail, phone);
        });

        verify(userRepository, times(1)).findByEmail(existingEmail);
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    public void testRegisterUserWithValidDetails() {
        // Arrange
        UserRepository userRepository = mock(UserRepository.class);
        UserService userService = new UserService();
        ReflectionTestUtils.setField(userService, "userRepository", userRepository);

        String username = "newUser";
        String password = "password123";
        String email = "newuser@example.com";
        String phone = "1234567890";

        when(userRepository.findByUsername(username)).thenReturn(Optional.empty());
        when(userRepository.findByEmail(email)).thenReturn(null);
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

        // Act
        User registeredUser = userService.registerUser(username, password, email, phone);

        // Assert
        assertNotNull(registeredUser);
        assertEquals(email, registeredUser.getUsername());
        assertTrue(new BCryptPasswordEncoder().matches(password, registeredUser.getPassword()));
        assertEquals(email, registeredUser.getEmail());
        assertEquals(phone, registeredUser.getPhone());
        assertEquals("Staff", registeredUser.getRole());
        assertNotNull(registeredUser.getVerificationToken());
        assertFalse(registeredUser.isVerified());
        assertTrue(registeredUser.getTokenExpiryTime() > System.currentTimeMillis());

        verify(userRepository, times(1)).findByUsername(username);
        verify(userRepository, times(1)).findByEmail(email);
        verify(userRepository, times(1)).save(any(User.class));
    }

    @Test
    public void testAuthenticateWithIncorrectPassword() {
        // Arrange
        UserRepository userRepository = mock(UserRepository.class);
        UserService userService = new UserService();
        ReflectionTestUtils.setField(userService, "userRepository", userRepository);

        String email = "user@example.com";
        String correctPassword = "correctPassword";
        String incorrectPassword = "wrongPassword";

        User user = new User();
        user.setEmail(email);
        user.setPassword(new BCryptPasswordEncoder().encode(correctPassword));
        user.setVerified(true);

        when(userRepository.findByEmail(email)).thenReturn(user);

        // Act
        boolean result = userService.authenticate(email, incorrectPassword);

        // Assert
        assertFalse(result);
        verify(userRepository, times(1)).findByEmail(email);
    }

    @Test
    public void testAuthenticateWithUnverifiedUser() {
        // Arrange
        UserRepository userRepository = mock(UserRepository.class);
        UserService userService = new UserService();
        ReflectionTestUtils.setField(userService, "userRepository", userRepository);

        String email = "unverified@example.com";
        String password = "password123";

        User unverifiedUser = new User();
        unverifiedUser.setEmail(email);
        unverifiedUser.setPassword(new BCryptPasswordEncoder().encode(password));
        unverifiedUser.setVerified(false);

        when(userRepository.findByEmail(email)).thenReturn(unverifiedUser);

        // Act
        boolean result = userService.authenticate(email, password);

        // Assert
        assertFalse(result);
        verify(userRepository, times(1)).findByEmail(email);
    }

    @Test
    public void testUpdatePhoneNumberForExistingUser() {
        // Arrange
        UserRepository userRepository = mock(UserRepository.class);
        UserService userService = new UserService();
        ReflectionTestUtils.setField(userService, "userRepository", userRepository);

        Long userId = 1L;
        String newPhone = "9876543210";
        User existingUser = new User();
        existingUser.setId(userId);
        existingUser.setUsername("testUser");
        existingUser.setPhone("1234567890");

        when(userRepository.findById(userId)).thenReturn(Optional.of(existingUser));
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

        // Act
        boolean result = userService.updatePhoneNumber(userId, newPhone);

        // Assert
        assertTrue(result);
        assertEquals(newPhone, existingUser.getPhone());
        verify(userRepository, times(1)).findById(userId);
        verify(userRepository, times(1)).save(existingUser);
    }

    @Test
    public void testUpdatePhoneNumberForNonExistentUser() {
        // Arrange
        UserRepository userRepository = mock(UserRepository.class);
        UserService userService = new UserService();
        ReflectionTestUtils.setField(userService, "userRepository", userRepository);

        Long nonExistentUserId = 999L;
        String newPhone = "9876543210";

        when(userRepository.findById(nonExistentUserId)).thenReturn(Optional.empty());

        // Act & Assert
        assertThrows(IllegalArgumentException.class, () -> {
            userService.updatePhoneNumber(nonExistentUserId, newPhone);
        });

        verify(userRepository, times(1)).findById(nonExistentUserId);
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    public void testUpdateUserCompanyInfo() {
        // Arrange
        UserRepository userRepository = mock(UserRepository.class);
        UserService userService = new UserService();
        ReflectionTestUtils.setField(userService, "userRepository", userRepository);

        Long userId = 1L;
        String companyName = "Test Company";
        String missionStatement = "Our mission is to test";
        String companyAddress = "123 Test St";
        String companySite = "www.testcompany.com";
        String userTitle = "Tester";

        User existingUser = new User();
        existingUser.setId(userId);

        when(userRepository.findById(userId)).thenReturn(Optional.of(existingUser));
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

        // Act
        User updatedUser = userService.updateUserCompanyInfo(userId, companyName, missionStatement, companyAddress, companySite, userTitle);

        // Assert
        assertNotNull(updatedUser);
        assertEquals(companyName, updatedUser.getCompanyName());
        assertEquals(missionStatement, updatedUser.getMissionStatement());
        assertEquals(companyAddress, updatedUser.getCompanyAddress());
        assertEquals(companySite, updatedUser.getCompanySite());
        assertEquals(userTitle, updatedUser.getUserTitle());

        verify(userRepository, times(1)).findById(userId);
        verify(userRepository, times(1)).save(existingUser);
    }

    @Test
    public void testUpdateUserCompanyInfoForNonExistentUser() {
        // Arrange
        UserRepository userRepository = mock(UserRepository.class);
        UserService userService = new UserService();
        ReflectionTestUtils.setField(userService, "userRepository", userRepository);

        Long nonExistentUserId = 999L;
        String companyName = "Test Company";
        String missionStatement = "Our mission is to test";
        String companyAddress = "123 Test St";
        String companySite = "www.testcompany.com";
        String userTitle = "Tester";

        when(userRepository.findById(nonExistentUserId)).thenReturn(Optional.empty());

        // Act & Assert
        assertThrows(IllegalArgumentException.class, () -> {
            userService.updateUserCompanyInfo(nonExistentUserId, companyName, missionStatement, companyAddress, companySite, userTitle);
        });

        verify(userRepository, times(1)).findById(nonExistentUserId);
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    public void testCountAllUsers() {
        // Arrange
        UserRepository userRepository = mock(UserRepository.class);
        UserService userService = new UserService();
        ReflectionTestUtils.setField(userService, "userRepository", userRepository);

        long expectedCount = 5;
        when(userRepository.count()).thenReturn(expectedCount);

        // Act
        long actualCount = userService.countAllUsers();

        // Assert
        assertEquals(expectedCount, actualCount);
        verify(userRepository, times(1)).count();
    }
}
