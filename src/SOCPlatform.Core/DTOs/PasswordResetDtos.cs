namespace SOCPlatform.Core.DTOs;

public class ForgotPasswordRequestDto
{
    /// <summary>Email address tied to the account.</summary>
    public string Email { get; set; } = string.Empty;
}

public class ResetPasswordRequestDto
{
    /// <summary>The plaintext token delivered via email.</summary>
    public string Token { get; set; } = string.Empty;

    public string NewPassword { get; set; } = string.Empty;
}
