package com.security.v2;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;

@RestController
@RequestMapping("/auth")
@AllArgsConstructor
public class AuthController {
  private final AuthenticationManager authenticationManager;
  private final UserRepository userRepository;
  private final PasswordEncoder encoder;
  private final JwtService jwtService;
  private final JwtConfig jwtConfig;

  @PostMapping("/signin")
  public ResponseEntity<User> signin(@RequestBody User user) {
    user.setPassword(encoder.encode(user.getPassword()));
    user.setRole(Role.USER);
    User savedUser = userRepository.save(user);
    return ResponseEntity.ok(savedUser);
  }

  @PostMapping("/login")
  public ResponseEntity<JwtResponse> login(@RequestBody LoginRequest user,
      HttpServletResponse response) {
    authenticationManager.authenticate(
        new UsernamePasswordAuthenticationToken(
            user.getEmail(), user.getPassword()));

    var foundUser = userRepository.findByEmail(user.getEmail()).orElseThrow(null);

    var accessToken = jwtService.generateAccessToken(foundUser);
    var refreshToken = jwtService.generateRefreshToken(foundUser);

    var cookie = new Cookie("refreshToken", refreshToken);
    cookie.setHttpOnly(true);
    cookie.setPath("/auth/refresh");
    cookie.setMaxAge(jwtConfig.getRefreshTokenExpiration());
    cookie.setSecure(false);

    response.addHeader("Set-Cookie", String.format("refreshToken=%s; HttpOnly; Path=/; Max-Age=%d; SameSite=Lax%s",
        refreshToken,
        7 * 24 * 60 * 60,
        "Secure"));

    response.addCookie(cookie);

    return ResponseEntity.ok(new JwtResponse(accessToken));
  }

  @PostMapping("/refresh")
  public ResponseEntity<JwtResponse> refresh(@CookieValue(value = "refreshToken") String refreshToken) {
    if (!jwtService.validateToken(refreshToken)) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }

    var userId = jwtService.getUserIdFromToken(refreshToken);
    var user = userRepository.findById(userId).orElseThrow();
    var accessToken = jwtService.generateAccessToken(user);

    return ResponseEntity.ok(new JwtResponse(accessToken));
  }

  @GetMapping("/me")
  public ResponseEntity<User> me() {
    var authentication = SecurityContextHolder.getContext().getAuthentication();
    var userId = (Long) authentication.getPrincipal();
    var user = userRepository.findById(userId).orElse(null);
    if (user == null) {
      return ResponseEntity.notFound().build();
    }
    return ResponseEntity.ok(user);
  }

  @ExceptionHandler(BadCredentialsException.class)
  public ResponseEntity<Void> handleBadCredentialException() {
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
  }
}
