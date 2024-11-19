package signature_generator.example.signature_generator.controller;
import lombok.RequiredArgsConstructor;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import signature_generator.example.signature_generator.auth.controller.UserController;
import signature_generator.example.signature_generator.auth.service.UserService;

import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertEquals;

@SpringBootTest
@ExtendWith(MockitoExtension.class)
@RequiredArgsConstructor
public class UserControllerTest {

    @Mock
    private UserService userService;

    @InjectMocks
    private UserController userController;

    @Test
    void updatePhone_shouldReturnBadRequestWhenPhoneNumberIsNotProvided() {
        // Arrange
        Long userId = 1L;
        Map<String, String> phoneRequest = new HashMap<>();
        phoneRequest.put("phone", "");

        // Act
        ResponseEntity<?> response = userController.updatePhone(userId, phoneRequest);

        // Assert
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals("Phone number is required", response.getBody());
    }

}

