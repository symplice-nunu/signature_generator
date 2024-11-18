package signature_generator.example.signature_generator.auth.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    @Value("${jwt.secret.key}")
    private String secretKey;
    private static final String SECRET_KEY = "432417e75e7ad54a0be770f3d793f0881917e89b9e6aca5e020996075569ce96ee5f5f38e7b1bec68bf42915b044ed5c99dc1fa9d12c6e4315a11d922730bf0eaada31e73958e588019f9b75c2c4ca59a90ca49a9a6d09dc391313930e8e4c9365742e95da00eb66f7457e19dd493eeecf7167b51d9344b5f026d87ee6ba613aaece0fba34589266af6e8ec80230d7fa41ea80da2bca2e015843c83fd98a5bb632e3ee59e34bf68692f18d6bb6731e81445366e3127700370925ef3286782cde28a71d67ccce4aecf5a93b8995c7cf982d6c27494521332ce185fecee61f6b4d439d678d9eb2027ed312ba78014cf7367a4b6c7fca3666792cbeea2f8c06e858"; // Secret Key
    private static final long EXPIRATION_TIME = 86400000;

    // Build the token with claims, subject, issued date, expiration, and signature
    public String buildToken(String username,Long userId) {

        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();

//        return Jwts.builder()
//                .setSubject(username)
//                .claim("userId", userId)
//                .setIssuedAt(new Date())
//                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
//                .signWith(SignatureAlgorithm.HS256, SECRET_KEY)
//                .compact();
    }

    // Extract username from the token
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    // Generic claim extraction
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    // Extract all claims from the token
    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    // Validate token with user details and check for expiration
    public Boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    // Check if the token is expired
    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    // Extract expiration date from the token
    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    // Get signing key from the secret key
    private Key getSignInKey() {
        byte[] keyBytes = secretKey.getBytes();
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
