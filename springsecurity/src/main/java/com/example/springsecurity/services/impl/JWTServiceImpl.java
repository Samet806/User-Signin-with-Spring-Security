package com.example.springsecurity.services.impl;

import com.example.springsecurity.entities.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Component
public class JWTServiceImpl  {

    public String generateToken(UserDetails userDetails)
    {
        return Jwts.builder().setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis()+1000*60*24))
                .signWith(getSigninKey(), SignatureAlgorithm.HS256)
                .compact();
    }
    public String extractUsername(String token)
    {
        return extractClaims(token,Claims::getSubject);
    }

    private <T> T extractClaims(String token, Function<Claims,T> claimsResolver)
    {
        final Claims claims=exractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims exractAllClaims(String token) {
        Claims claims = Jwts.parser()
                .setSigningKey(getSigninKey()).build()
                .parseClaimsJws(token)
                .getBody();
        return claims;
    }

    private Key getSigninKey() {
        byte[] key= Decoders.BASE64.decode("b313a21908df55c9e322e3c65a4b0b7561ab1594ca806b3affbc0d769a1");
        return Keys.hmacShaKeyFor(key);
    }
    public boolean isTokenValid(String token,UserDetails userDetails)
    {
        final String username=extractUsername(token);
        return  (username.equals(userDetails.getUsername()) && !isTokenExpired(token) );
    }

    private boolean isTokenExpired(String token) {
        return extractClaims(token,Claims::getExpiration).before(new Date());
    }



    public String generateRefreshToken(Map<String, Object> extraClaims, UserDetails userDetails)
    {
        return Jwts.builder().setClaims(extraClaims).setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis()+604800000))
                .signWith(getSigninKey(), SignatureAlgorithm.HS256)
                .compact();
    }
}
