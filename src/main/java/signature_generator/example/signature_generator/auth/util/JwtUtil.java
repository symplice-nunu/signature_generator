package signature_generator.example.signature_generator.auth.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.util.Date;

public class JwtUtil {

    private static final String SECRET_KEY = "432417e75e7ad54a0be770f3d793f0881917e89b9e6aca5e020996075569ce96ee5f5f38e7b1bec68bf42915b044ed5c99dc1fa9d12c6e4315a11d922730bf0eaada31e73958e588019f9b75c2c4ca59a90ca49a9a6d09dc391313930e8e4c9365742e95da00eb66f7457e19dd493eeecf7167b51d9344b5f026d87ee6ba613aaece0fba34589266af6e8ec80230d7fa41ea80da2bca2e015843c83fd98a5bb632e3ee59e34bf68692f18d6bb6731e81445366e3127700370925ef3286782cde28a71d67ccce4aecf5a93b8995c7cf982d6c27494521332ce185fecee61f6b4d439d678d9eb2027ed312ba78014cf7367a4b6c7fca3666792cbeea2f8c06e858"; // Secret Key
    private static final long EXPIRATION_TIME = 86400000;  // Token expiry time (1 day)

    // Generate JWT token
    public static String generateToken(String username, Long userId) {
        return Jwts.builder()
                .setSubject(username)
                .claim("userId", userId)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(SignatureAlgorithm.HS256, SECRET_KEY)
                .compact();
    }

    // Validate JWT token
    public static boolean validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(SECRET_KEY).build().parseClaimsJws(token); // Use new API
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    // Get username from token
    public static String extractUsername(String token) {
        Claims claims = parseClaims(token);
        return claims.getSubject();  // Extract the username
    }

    // Get userId from token
    public static Long extractUserId(String token) {
        Claims claims = parseClaims(token);
        return Long.parseLong(claims.get("userId").toString());  // Extract the userId
    }

    // Helper method to parse claims from the token
    private static Claims parseClaims(String token) {
        return Jwts.parserBuilder().setSigningKey(SECRET_KEY).build().parseClaimsJws(token).getBody();  // Parse claims from the token
    }

    // Check if the token is expired
    public static boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    // Get expiration date from token
    private static Date extractExpiration(String token) {
        Claims claims = parseClaims(token);
        return claims.getExpiration();
    }
}
