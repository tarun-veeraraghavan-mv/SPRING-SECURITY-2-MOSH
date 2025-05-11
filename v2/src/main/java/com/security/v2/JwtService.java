package com.security.v2;

import java.util.Date;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.AllArgsConstructor;

@Service
@AllArgsConstructor
public class JwtService {
  private final JwtConfig jwtConfig;

  public String generateAccessToken(User user) {
    return generateToken(user, jwtConfig.getAccessTokenExpiration());
  }

  public String generateRefreshToken(User user) {
    return generateToken(user, jwtConfig.getRefreshTokenExpiration());
  }

  public String generateToken(User user, long tokenExpiration) {
    return Jwts.builder()
        .subject(user.getId().toString())
        .claim("email", user.getEmail())
        .claim("name", user.getName())
        .issuedAt(new Date())
        .expiration(new Date(System.currentTimeMillis() * 1000 * tokenExpiration))
        .signWith(jwtConfig.getSecretKey())
        .compact();
  }

  public boolean validateToken(String token) {
    try {
      var claims = getClaims(token);
      return claims.getExpiration().after(new Date());
    } catch (JwtException ex) {
      return false;
    }

  }

  private Claims getClaims(String token) {
    var claims = Jwts.parser()
        .verifyWith(jwtConfig.getSecretKey())
        .build()
        .parseSignedClaims(token)
        .getPayload();

    return claims;
  }

  public Long getUserIdFromToken(String token) {
    return Long.valueOf(getClaims(token).getSubject());
  }
}
