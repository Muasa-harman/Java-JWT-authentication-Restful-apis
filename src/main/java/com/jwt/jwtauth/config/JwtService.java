package com.jwt.jwtauth.config;

import org.springframework.stereotype.Service;

import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    private static final String SECRET_KEY = "";
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims,T>claimsResolver){
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public String generateToken(userDetails userDetails){
        return generateToken(new HashMap<>(),userDetails);
    }

    public String generateToken(
            Map<String, Object> extractClaims,userDetails userDetails
    ){
        return JwtService
                .builder()
                .setClaims(extractClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
                .signWith(getSignInKey(), SignatureAlgorithm.hs256)
                .compact();
    }

    public boolean isTokenValid(String token, UserDetails userDetails){
        final String username = extractUsername(token);
                return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private Date extractExpiration(String token){
        return extractClaim(token, Claims::getExpiration);
    }

    private boolean isTokenExpired(String token){
        return extractExpiration(token).before(new Date());
    }

    private Claims extractAllClaims(String token){

        return Jwts
                .parserBuilder()
                .setSigninKey(getSignInKey())
                .build()
                .parseClaimJws(token)
                .getBody();

    }

//    private Object getSignInKey() {
//    }

    private Object getSignInKey() {
    byte[] keyBytes = Base64.Decoders.BASE64.decode(SECRET_KEY);
    return Keys.hmacShaKeyFor(KeyBytes);
    }
}
