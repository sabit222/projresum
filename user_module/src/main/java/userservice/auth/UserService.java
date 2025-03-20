package userservice.auth;


import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import userservice.model.UpdateUserRequest;
import userservice.model.User;
import userservice.repository.UserRepository;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserService {

    private final PasswordEncoder passwordEncoder;
    private final UserRepository repository;

    public Optional<User> getUserByFirstname(String firstname){
        return repository.findByFirstname(firstname);
    }

    public void updateUserProfile(String email, UpdateUserRequest userRequest){
        User user = repository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (userRequest.getFirstname() != null){
            user.setFirstname(userRequest.getFirstname());
        }
        if (userRequest.getLastname() != null){
            user.setLastname(userRequest.getLastname());
        }
        if (userRequest.getEmail() != null && !userRequest.getEmail().equals(user.getEmail())){
            user.setEmail(userRequest.getEmail());
        }
        repository.save(user);
    }
}
