package ch.luschmar.jxa.auth.server.api.account;


import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record LoginRequest(@NotBlank(message = "email cannot be null")
                           @Email
                           String email,
                           @NotBlank(message = "authPW cannot be null")
                           @Size(min = 64, max = 64)
                           String authPW) {
}
