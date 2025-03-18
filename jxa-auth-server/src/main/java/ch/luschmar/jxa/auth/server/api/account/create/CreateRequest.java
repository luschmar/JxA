package ch.luschmar.jxa.auth.server.api.account.create;


import ch.luschmar.jxa.auth.server.api.account.login.VerificationMethod;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record CreateRequest(@NotBlank(message = "email cannot be null")
                            @Email
                            String email,
                            @NotBlank(message = "authPW cannot be null")
                            @Size(min = 64, max = 64)
                            String authPW,
                            String authPWVersion2,
                            String wrapKb,
                            String wrapKbVersion2,
                            String clientSalt,
                            String service,
                            String redirectTo,
                            String resume,
                            MetricsContent metricsContent,
                            String style,
                            VerificationMethod verificationMethod,
                            boolean atLeast18AtReg) {
}
