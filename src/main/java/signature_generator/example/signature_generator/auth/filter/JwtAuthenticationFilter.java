package signature_generator.example.signature_generator.auth.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import signature_generator.example.signature_generator.auth.model.User;
import signature_generator.example.signature_generator.auth.service.JwtService;
import signature_generator.example.signature_generator.auth.service.UserService;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserService userService;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;

        // Check if header contains Bearer token
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        // Extract JWT from Authorization header
        jwt = authHeader.substring(7);

        // Extract username from JWT token
        userEmail = jwtService.extractUsername(jwt);

        // Validate token and set the authentication context
        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            User userDetails = userService.findByEmail(userEmail);

            if (jwtService.isTokenValid(jwt, userDetails)) {
                System.out.println("Token is valid. Setting authentication.");

                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
                System.out.println("SecurityContextHolder set with Authentication: "
                        + SecurityContextHolder.getContext().getAuthentication());
            }
        }

        // Continue with the filter chain
        filterChain.doFilter(request, response);
    }
}
