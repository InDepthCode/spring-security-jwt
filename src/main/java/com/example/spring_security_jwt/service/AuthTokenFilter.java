package com.example.spring_security_jwt.service;

import com.example.spring_security_jwt.entity.User;
import com.example.spring_security_jwt.security.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@Slf4j
public class AuthTokenFilter extends OncePerRequestFilter {

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private CustomUserDetailsService customUserDetailsService;



    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        /*Think of this method as the security guard at the gate:
        - Checks if you have a valid ID card (JWT).
        - If valid, looks up your details in the system (DB).
        - Stamps your entry pass (SecurityContext).
        - Lets you into the building (controller).
        */
        try{
            String jwt = parseJwt(request);
            if(jwt != null && jwtUtil.validateToken(jwt)){
                final String username = jwtUtil.getUsername(jwt);
                final UserDetails userDetails = customUserDetailsService.loadUserByUsername(username);
                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            }
        }  catch (Exception e) {
        log.error("Cannot set user authentication: {}", e.getMessage());  // ✅ JUST LOG IT
    }
        filterChain.doFilter(request, response);

    }

        /*- bearerToken = "Bearer eyJhbGciOiJIUzI1NiJ9..."
        - After substring(7) → "eyJhbGciOiJIUzI1NiJ9..." (the actual JWT).

        ✅ So in short:
        This method peels off the “Bearer ” prefix from the Authorization header and hands you the raw JWT string, which you then validate and parse for the username.
        */

    private String parseJwt(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}
