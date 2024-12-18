package com.example.demo.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.web.bind.annotation.*;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/user")
public class HomeController {

    @PostMapping("/login")
    @CrossOrigin(origins = "*")
    public Map<String, String> login(HttpServletRequest request) {
        Map<String, String> response = new HashMap<>();
        String authHeader = request.getHeader("Authorization");

        if (authHeader == null || !authHeader.startsWith("Basic ")) {
            response.put("message", "Authorization header missing or invalid.");
            return response;
        }

        try {
            String base64Credentials = authHeader.substring(6);
            String credentials = new String(Base64.getDecoder().decode(base64Credentials));
            String[] userDetails = credentials.split(":", 2);

            if (userDetails.length != 2) {
                response.put("message", "Malformed credentials.");
                return response;
            }

            String username = userDetails[0];
            String password = userDetails[1];

            if ("user".equals(username) && "password".equals(password)) {
                HttpSession session = request.getSession(true);
                session.setAttribute("username", username);
                response.put("message", "Login Successful! Access /home for secured content.");
            } else {
                response.put("message", "Invalid username or password.");
            }
        } catch (IllegalArgumentException ex) {
            response.put("message", "Failed to decode credentials: " + ex.getMessage());
        }

        return response;
    }

    @GetMapping("/home")
    public Map<String, String> home(HttpServletRequest request) {
        Map<String, String> response = new HashMap<>();
        HttpSession session = request.getSession(false);

        if (session == null) {
            response.put("message", "Access denied. No active session. Please log in first.");
        } else if (session.getAttribute("username") != null) {
            response.put("message", "Welcome to the secured home endpoint!");
            response.put("username", session.getAttribute("username").toString());
        } else {
            response.put("message", "Access denied. Session is invalid or missing required attributes.");
        }

        return response;
    }

    @GetMapping("/logout")
    public Map<String, String> logout(HttpServletRequest request) {
        Map<String, String> response = new HashMap<>();
        HttpSession session = request.getSession(false);

        if (session != null) {
            session.invalidate();
            response.put("message", "You have been successfully logged out.");
        } else {
            response.put("message", "No active session found. You are already logged out.");
        }

        return response;
    }
}
