package 实验3;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class LoginController {

    private final AuthenticationManager authenticationManager;
    private final CustomUserDetailsService userDetailsService;
    private final JwtUtil jwtUtil;
    private final PasswordEncoder passwordEncoder;

    public LoginController(AuthenticationManager authenticationManager, CustomUserDetailsService userDetailsService,
                           JwtUtil jwtUtil, PasswordEncoder passwordEncoder) {
        this.authenticationManager = authenticationManager;
        this.userDetailsService = userDetailsService;
        this.jwtUtil = jwtUtil;
        this.passwordEncoder = passwordEncoder;
    }

    @PostMapping("/login")
    public ApiResponse login(@RequestBody LoginForm loginForm) {
        // Authenticate the user
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginForm.getUsername(), loginForm.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);

        // Generate JWT token
        UserDetails userDetails = userDetailsService.loadUserByUsername(loginForm.getUsername());
        String jwtToken = jwtUtil.generateToken(userDetails);

        return new ApiResponse(true, "Login successful", jwtToken);
    }

    @GetMapping("/protected-resource")
    public ApiResponse getProtectedResource() {
        return new ApiResponse(true, "You have accessed the protected resource");
    }

    @GetMapping("/unprotected-resource")
    public ApiResponse getUnprotectedResource() {
        return new ApiResponse(true, "You have accessed the unprotected resource");
    }
}
