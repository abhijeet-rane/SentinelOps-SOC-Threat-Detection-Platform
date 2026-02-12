using FluentValidation;
using SOCPlatform.Core.DTOs;

namespace SOCPlatform.API.Validators;

public class LoginRequestValidator : AbstractValidator<LoginRequestDto>
{
    public LoginRequestValidator()
    {
        RuleFor(x => x.Username)
            .NotEmpty().WithMessage("Username is required")
            .MaximumLength(50)
            .Matches(@"^[a-zA-Z0-9._-]+$").WithMessage("Username contains invalid characters");

        RuleFor(x => x.Password)
            .NotEmpty().WithMessage("Password is required")
            .MaximumLength(128);
    }
}

public class RegisterUserValidator : AbstractValidator<RegisterUserDto>
{
    public RegisterUserValidator()
    {
        RuleFor(x => x.Username)
            .NotEmpty()
            .MinimumLength(3).MaximumLength(50)
            .Matches(@"^[a-zA-Z0-9._-]+$").WithMessage("Username may only contain letters, numbers, dots, underscores, hyphens");

        RuleFor(x => x.Email)
            .NotEmpty()
            .EmailAddress().WithMessage("A valid email address is required")
            .MaximumLength(255);

        RuleFor(x => x.Password)
            .NotEmpty()
            .MinimumLength(10).WithMessage("Password must be at least 10 characters")
            .MaximumLength(128)
            .Matches(@"[A-Z]").WithMessage("Password must contain at least one uppercase letter")
            .Matches(@"[a-z]").WithMessage("Password must contain at least one lowercase letter")
            .Matches(@"[0-9]").WithMessage("Password must contain at least one digit")
            .Matches(@"[^a-zA-Z0-9]").WithMessage("Password must contain at least one special character");

        RuleFor(x => x.RoleId)
            .NotEmpty().WithMessage("Role is required");
    }
}

public class RefreshTokenValidator : AbstractValidator<RefreshTokenRequestDto>
{
    public RefreshTokenValidator()
    {
        RuleFor(x => x.RefreshToken)
            .NotEmpty().WithMessage("Refresh token is required");
    }
}

public class LogIngestionValidator : AbstractValidator<LogIngestionDto>
{
    private static readonly string[] ValidSeverities = { "Low", "Medium", "High", "Critical" };

    public LogIngestionValidator()
    {
        RuleFor(x => x.EndpointId)
            .NotEmpty();

        RuleFor(x => x.Source)
            .NotEmpty().MaximumLength(100);

        RuleFor(x => x.EventType)
            .NotEmpty().MaximumLength(100);

        RuleFor(x => x.Severity)
            .Must(s => ValidSeverities.Contains(s))
            .WithMessage("Severity must be Low, Medium, High, or Critical");

        RuleFor(x => x.RawData)
            .MaximumLength(1_000_000).WithMessage("RawData exceeds 1MB limit");

        RuleFor(x => x.SourceIP)
            .MaximumLength(45)
            .Matches(@"^[\d.:a-fA-F]+$").When(x => !string.IsNullOrEmpty(x.SourceIP))
            .WithMessage("SourceIP must be a valid IPv4 or IPv6 address");

        RuleFor(x => x.Hostname)
            .MaximumLength(255);

        RuleFor(x => x.Timestamp)
            .NotEmpty()
            .LessThanOrEqualTo(DateTime.UtcNow.AddMinutes(5)).WithMessage("Timestamp cannot be in the future");
    }
}

public class BatchLogIngestionValidator : AbstractValidator<BatchLogIngestionDto>
{
    public BatchLogIngestionValidator()
    {
        RuleFor(x => x.EndpointId)
            .NotEmpty();

        RuleFor(x => x.AgentVersion)
            .NotEmpty().MaximumLength(20);

        RuleFor(x => x.Logs)
            .NotEmpty().WithMessage("At least one log entry is required")
            .Must(logs => logs.Count <= 1000).WithMessage("Batch size cannot exceed 1000 entries");

        RuleForEach(x => x.Logs).SetValidator(new LogIngestionValidator());
    }
}
