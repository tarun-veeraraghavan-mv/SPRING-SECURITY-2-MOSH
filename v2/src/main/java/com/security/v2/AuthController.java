package com.security.v2;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.AllArgsConstructor;

@RestController
@RequestMapping("/auth")
@AllArgsConstructor
public class AuthController {
  private final AuthenticationManager authenticationManager;
  private final UserRepository userRepository;
  private final PasswordEncoder encoder;
  private final JwtService jwtService;

  @PostMapping("/signin")
  public ResponseEntity<User> signin(@RequestBody User user) {
    user.setPassword(encoder.encode(user.getPassword()));
    User savedUser = userRepository.save(user);
    return ResponseEntity.ok(savedUser);
  }

  @PostMapping("/login")
  public ResponseEntity<JwtResponse> login(@RequestBody LoginRequest user) {
    authenticationManager.authenticate(
        new UsernamePasswordAuthenticationToken(
            user.getEmail(), user.getPassword()));

    var token = jwtService.generateToken(user.getEmail());
    return ResponseEntity.ok(new JwtResponse(token));
  }

  @ExceptionHandler(BadCredentialsException.class)
  public ResponseEntity<Void> handleBadCredentialException() {
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
  }
}
