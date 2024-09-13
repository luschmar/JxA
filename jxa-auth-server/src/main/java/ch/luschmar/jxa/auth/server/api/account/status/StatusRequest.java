package ch.luschmar.jxa.auth.server.api.account.status;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record StatusRequest(@Email @NotBlank String email, boolean thirdPartyAuthStatus, String checkDomain) {
}
