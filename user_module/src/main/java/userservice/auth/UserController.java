package userservice.auth;


import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;
import userservice.model.UpdateUserRequest;
import userservice.model.User;

@RestController
@RequestMapping("/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService service;

    @GetMapping("/firstname/{firstname}")
    public ResponseEntity<User> getUserByFirstname(@PathVariable String firstname){
        return service.getUserByFirstname(firstname)
                .map(ResponseEntity::ok)
                .orElseThrow(() -> new RuntimeException("User with name " + firstname + " not found"));
    }

    @PutMapping("/profile/{email}")
    public ResponseEntity<String> updateUserProfile(@RequestBody UpdateUserRequest updateUser,
                                                    @AuthenticationPrincipal UserDetails userDetails){
        String email = userDetails.getUsername();
        service.updateUserProfile(email, updateUser);

        return ResponseEntity.ok("Profile update successfully");

    }
}
