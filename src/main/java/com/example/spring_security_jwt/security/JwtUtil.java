package com.example.spring_security_jwt.security;


import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;

@Component
@Slf4j
public class JwtUtil {

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.expiration}")
    private Long expiration;


    private SecretKey key;

    @PostConstruct // - @PostConstruct runs, converting the secret string into a cryptographic key.

    public void init() {
        this.key = Keys.hmacShaKeyFor(secret.getBytes());
    }

    // The function that actually generates a jwt token

    public String generateToken(String username){
        return Jwts.builder()
                .setSubject(username) // payload: who the token is about
                .setIssuedAt(new Date()) // when it was created
                .expiration(new Date(System.currentTimeMillis() + expiration)) // expiry
                .signWith(key) // sign with the secret key
                .compact(); // build the final token string


    }
    /*- getUsername(token)
- Its job is to extract the sub (subject/username) claim from the token.
- But to extract safely, the parser also verifies the signature internally (so you don’t accidentally read a tampered token).
- That’s why it looks like validation is happening again — but here it’s a side effect of parsing.*/


    //  Now we need to get username from jwt token
    public String getUsername(String token){
        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseClaimsJws(token)
                .getPayload()
                .getSubject();

    }


    /*- validateToken(token)
- Its only job is to check: “Is this token structurally correct, signed with my secret key, and not expired?”
- It doesn’t care about the username or any other claim.
- It’s a gatekeeper: if this fails, you don’t even bother extracting anything.

*/
    // Validate if token given to use is valid

    public boolean validateToken(String token){
        try{
            Jwts.parser()
                    .verifyWith(key)
                    .build()
                    .parseClaimsJws(token);

                    return true;
        }
        catch(Exception e){
            log.error(e.getMessage());
        }

        return false;
    }
}



/*  How They Work Together
- Login → generate token with .setSubject(username).
- Request with token →
- validateToken(token) checks if it’s still valid.
- If valid, getUsername(token) extracts the username ("amrut").
- Spring Security uses that username to load user details and authorize access.
*/