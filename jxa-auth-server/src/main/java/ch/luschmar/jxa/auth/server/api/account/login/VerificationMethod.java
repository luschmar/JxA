package ch.luschmar.jxa.auth.server.api.account.login;

public enum VerificationMethod {
    EMAIL,
    EMAIL_OTP,
    EMAIL_2FA,
    EMAIL_CAPTCHA,
    TOTP_2FA
}
