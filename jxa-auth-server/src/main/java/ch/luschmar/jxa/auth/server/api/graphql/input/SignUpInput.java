package ch.luschmar.jxa.auth.server.api.graphql.input;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import static ch.luschmar.jxa.auth.server.api.account.RequestConstants.AUTH_PW_HEX_DATA;

public record SignUpInput(@NotBlank(message = "email cannot be null")
                          @Email
                          String email,
                          @NotBlank(message = "authPW cannot be null")
                          @Size(min = 64, max = 64)
                          @Pattern(regexp = AUTH_PW_HEX_DATA)
                          String authPW
                          //String authPWVersion2,
                          //String wrapKb,
                          //String wrapKbVersion2,
                          //String clientSalt,
                          //String service,
                          //String redirectTo,
                          //String resume,
                          //MetricsContent metricsContent,
                          //String style,
                          //VerificationMethod verificationMethod,
                          //boolean atLeast18AtReg
) {
}
