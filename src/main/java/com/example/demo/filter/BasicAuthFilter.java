package com.example.demo.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import java.io.IOException;
import java.util.Base64;
import java.util.Set;

public class BasicAuthFilter extends BasicAuthenticationFilter {

    private final Set<String> excludedEndpoints = Set.of("/api/user/home", "/api/user/logout");

    public BasicAuthFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        String requestURI = request.getRequestURI();

        if (excludedEndpoints.contains(requestURI)) {
            chain.doFilter(request, response);
            return;
        }

        String header = request.getHeader("Authorization");
        if (header == null || !header.startsWith("Basic ")) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.getWriter().write("Authorization header missing or invalid. Expected 'Basic [Base64EncodedCredentials]'.");
            response.getWriter().flush();
            return;
        }

        try {
            String base64Credentials = header.substring(6);
            String credentials = new String(Base64.getDecoder().decode(base64Credentials));
            String[] userDetails = credentials.split(":", 2);

            if (userDetails.length != 2) {
                throw new IllegalArgumentException("Malformed credentials");
            }

            String username = userDetails[0];
            String password = userDetails[1];

            UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password);
            Authentication auth = getAuthenticationManager().authenticate(authToken);

            if (auth.isAuthenticated()) {
                chain.doFilter(request, response);
            } else {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write("Authentication failed. Invalid username or password.");
            }
        } catch (AuthenticationException e) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("Authentication failed: " + e.getMessage());
        } catch (IllegalArgumentException e) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.getWriter().write("Malformed credentials: " + e.getMessage());
        } catch (Exception e) {
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.getWriter().write("Unexpected error: " + e.getMessage());
        }
    }

}
