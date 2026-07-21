using System.Net.Mail;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using ShuaiTunnel.Server.Authentication;
using ShuaiTunnel.Server.Configuration;
using ShuaiTunnel.Server.Data;
using ShuaiTunnel.Server.Data.Entities;
using ShuaiTunnel.Server.Security;

namespace ShuaiTunnel.Server.Management;

public sealed class RegistrationService
{
    private readonly TunnelDbContext _db;
    private readonly AuthOptions _auth;
    private readonly LocalTokenService _tokens;
    private readonly ITurnstileVerifier _turnstile;
    private readonly IRegistrationEmailSender _emailSender;

    public RegistrationService(TunnelDbContext db, IOptions<AuthOptions> auth,
        LocalTokenService tokens, ITurnstileVerifier turnstile,
        IRegistrationEmailSender emailSender)
    {
        _db = db;
        _auth = auth.Value;
        _tokens = tokens;
        _turnstile = turnstile;
        _emailSender = emailSender;
    }

    public bool Available => _auth.RegistrationEnabled
        && _tokens.IsPasswordLoginEnabled
        && _auth.EmailVerificationEnabled
        && _emailSender.Configured
        && _turnstile.Enabled
        && _turnstile.Configured;

    public async Task<RegistrationChallengeResponse> RequestAsync(string? rawUsername,
        string? rawEmail, string? rawPassword, CancellationToken cancellationToken)
    {
        RequireAvailable();
        var username = NormalizeUsername(rawUsername);
        if (string.Equals(username, _auth.Username, StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("该用户名不可用");
        }
        var password = RequirePassword(rawPassword);
        var email = NormalizeEmail(rawEmail);

        if (await _db.ManagementUsers.AsNoTracking()
                .AnyAsync(user => user.Username.ToLower() == username.ToLower(), cancellationToken)
                .ConfigureAwait(false))
        {
            throw new InvalidOperationException("用户名已存在: " + username);
        }
        if (await _db.ManagementUserEmails.AsNoTracking()
                .AnyAsync(item => item.Email.ToLower() == email, cancellationToken)
                .ConfigureAwait(false))
        {
            throw new InvalidOperationException("该邮箱已注册");
        }

        var now = DateTimeOffset.UtcNow;
        var expired = await _db.ManagementRegistrationChallenges
            .Where(item => item.ExpiresAt <= now)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);
        if (expired.Count > 0)
        {
            _db.ManagementRegistrationChallenges.RemoveRange(expired);
            await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }

        var normalizedUsername = username.ToLower();
        var existing = await _db.ManagementRegistrationChallenges
            .FirstOrDefaultAsync(item => item.Username.ToLower() == normalizedUsername
                    || item.Email.ToLower() == email,
                cancellationToken)
            .ConfigureAwait(false);
        if (existing is not null)
        {
            if (!string.Equals(existing.Username, username, StringComparison.OrdinalIgnoreCase)
                || !string.Equals(existing.Email, email, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException("用户名或邮箱正在等待验证");
            }
            if (existing.ResendAvailableAt > now)
            {
                var wait = Math.Max(1, (long)Math.Ceiling((existing.ResendAvailableAt - now).TotalSeconds));
                throw new RateLimitedException($"请在 {wait} 秒后重新发送验证码");
            }
            _db.ManagementRegistrationChallenges.Remove(existing);
            await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }

        var ttlSeconds = Math.Max(60, _auth.EmailCodeTtlSeconds);
        var cooldownSeconds = Math.Max(1, _auth.EmailResendCooldownSeconds);
        var registrationId = RandomRegistrationId();
        var code = RandomNumberGenerator.GetInt32(1_000_000).ToString("D6");
        var challenge = new ManagementRegistrationChallenge
        {
            RegistrationId = registrationId,
            Username = username,
            Email = email,
            PasswordHash = PasswordHasher.Hash(password),
            CodeHash = _tokens.RegistrationCodeHash(registrationId, code),
            AttemptsRemaining = Math.Max(1, _auth.EmailMaxAttempts),
            ExpiresAt = now.AddSeconds(ttlSeconds),
            ResendAvailableAt = now.AddSeconds(cooldownSeconds),
            CreatedAt = now,
            UpdatedAt = now,
        };
        _db.ManagementRegistrationChallenges.Add(challenge);
        try
        {
            await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (DbUpdateException)
        {
            throw new InvalidOperationException("用户名或邮箱正在等待验证");
        }

        try
        {
            await _emailSender.SendVerificationCodeAsync(email, username, code, ttlSeconds,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch
        {
            _db.ManagementRegistrationChallenges.Remove(challenge);
            try
            {
                await _db.SaveChangesAsync(CancellationToken.None).ConfigureAwait(false);
            }
            catch (DbUpdateException)
            {
                // A later cleanup pass will remove the short-lived challenge.
            }
            throw;
        }

        return new RegistrationChallengeResponse(registrationId, MaskEmail(email),
            challenge.ExpiresAt.ToString("O"), cooldownSeconds);
    }

    public async Task<LoginUser> VerifyAsync(string? rawRegistrationId, string? rawCode,
        CancellationToken cancellationToken)
    {
        RequireAvailable();
        var registrationId = (rawRegistrationId ?? string.Empty).Trim();
        var code = (rawCode ?? string.Empty).Trim();
        if (registrationId.Length is 0 or > 64 || code.Length != 6 || code.Any(ch => ch is < '0' or > '9'))
        {
            throw InvalidCode();
        }

        var challenge = await _db.ManagementRegistrationChallenges
            .FirstOrDefaultAsync(item => item.RegistrationId == registrationId, cancellationToken)
            .ConfigureAwait(false);
        var now = DateTimeOffset.UtcNow;
        if (challenge is null)
        {
            throw InvalidCode();
        }
        if (challenge.ExpiresAt <= now || challenge.AttemptsRemaining <= 0)
        {
            _db.ManagementRegistrationChallenges.Remove(challenge);
            await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
            throw InvalidCode();
        }

        var expected = Encoding.ASCII.GetBytes(challenge.CodeHash);
        var actual = Encoding.ASCII.GetBytes(_tokens.RegistrationCodeHash(registrationId, code));
        if (!CryptographicOperations.FixedTimeEquals(expected, actual))
        {
            challenge.AttemptsRemaining--;
            challenge.UpdatedAt = now;
            if (challenge.AttemptsRemaining <= 0)
            {
                _db.ManagementRegistrationChallenges.Remove(challenge);
            }
            await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
            throw InvalidCode();
        }

        if (await _db.ManagementUsers.AsNoTracking()
                .AnyAsync(user => user.Username.ToLower() == challenge.Username.ToLower(), cancellationToken)
                .ConfigureAwait(false))
        {
            throw new InvalidOperationException("用户名已存在: " + challenge.Username);
        }
        if (await _db.ManagementUserEmails.AsNoTracking()
                .AnyAsync(item => item.Email.ToLower() == challenge.Email.ToLower(), cancellationToken)
                .ConfigureAwait(false))
        {
            throw new InvalidOperationException("该邮箱已注册");
        }

        await using var transaction = await _db.Database.BeginTransactionAsync(cancellationToken)
            .ConfigureAwait(false);
        var user = new ManagementUser
        {
            Username = challenge.Username,
            TenantId = ManagementContext.NormalizeTenant(_auth.TenantId),
            PasswordHash = challenge.PasswordHash,
            Role = ManagementRole.User,
            Enabled = true,
            CreatedAt = now,
            UpdatedAt = now,
        };
        _db.ManagementUsers.Add(user);
        _db.ManagementUserEmails.Add(new ManagementUserEmail
        {
            Username = user.Username,
            Email = challenge.Email,
            VerifiedAt = now,
            CreatedAt = now,
            UpdatedAt = now,
        });
        _db.ManagementRegistrationChallenges.Remove(challenge);
        try
        {
            await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (DbUpdateException)
        {
            await transaction.RollbackAsync(CancellationToken.None).ConfigureAwait(false);
            throw new InvalidOperationException("用户名或邮箱已被注册");
        }

        return new LoginUser(user.Username, user.TenantId, user.Role, BuiltInAdmin: false);
    }

    public async Task DeleteExpiredChallengesAsync(CancellationToken cancellationToken)
    {
        var now = DateTimeOffset.UtcNow;
        var expired = await _db.ManagementRegistrationChallenges
            .Where(item => item.ExpiresAt <= now)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);
        if (expired.Count == 0)
        {
            return;
        }
        _db.ManagementRegistrationChallenges.RemoveRange(expired);
        await _db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

    private void RequireAvailable()
    {
        if (!Available)
        {
            throw new RegistrationUnavailableException("当前未开放邮箱验证注册");
        }
    }

    private static string NormalizeUsername(string? value)
    {
        var normalized = (value ?? string.Empty).Trim();
        if (normalized.Length == 0)
        {
            throw new ArgumentException("用户名不能为空");
        }
        if (normalized.Length > 80)
        {
            throw new ArgumentException("用户名过长");
        }
        return normalized;
    }

    private static string RequirePassword(string? value)
    {
        var normalized = (value ?? string.Empty).Trim();
        if (normalized.Length == 0)
        {
            throw new ArgumentException("密码不能为空");
        }
        if (normalized.Length > 120)
        {
            throw new ArgumentException("密码过长");
        }
        return normalized;
    }

    private static string NormalizeEmail(string? value)
    {
        var email = (value ?? string.Empty).Trim().ToLowerInvariant();
        if (email.Length == 0)
        {
            throw new ArgumentException("邮箱不能为空");
        }
        var at = email.LastIndexOf('@');
        var dot = email.LastIndexOf('.');
        if (email.Length > 254 || at <= 0 || dot <= at + 1 || dot == email.Length - 1
            || !MailAddress.TryCreate(email, out var address)
            || !string.Equals(address.Address, email, StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("邮箱格式无效");
        }
        return email;
    }

    private static string RandomRegistrationId()
    {
        var bytes = RandomNumberGenerator.GetBytes(24);
        return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    private static string MaskEmail(string email)
    {
        var at = email.IndexOf('@');
        var visible = Math.Min(2, at);
        return email[..visible] + "***" + email[at..];
    }

    private static ArgumentException InvalidCode() => new("验证码无效或已过期");
}

public sealed record RegistrationChallengeResponse(
    string RegistrationId,
    string EmailMasked,
    string ExpiresAt,
    long ResendAfterSeconds);

public sealed class RegistrationUnavailableException(string message) : UnauthorizedAccessException(message);

public sealed class RegistrationChallengeCleanupService : BackgroundService
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly AuthOptions _options;
    private readonly ILogger<RegistrationChallengeCleanupService> _logger;

    public RegistrationChallengeCleanupService(IServiceScopeFactory scopeFactory,
        IOptions<AuthOptions> options, ILogger<RegistrationChallengeCleanupService> logger)
    {
        _scopeFactory = scopeFactory;
        _options = options.Value;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var intervalMs = _options.EmailCleanupIntervalMs > 0
            ? _options.EmailCleanupIntervalMs
            : 3_600_000;
        using var timer = new PeriodicTimer(TimeSpan.FromMilliseconds(Math.Max(1_000, intervalMs)));
        await DeleteExpiredAsync(stoppingToken).ConfigureAwait(false);
        while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
        {
            await DeleteExpiredAsync(stoppingToken).ConfigureAwait(false);
        }
    }

    private async Task DeleteExpiredAsync(CancellationToken cancellationToken)
    {
        try
        {
            await using var scope = _scopeFactory.CreateAsyncScope();
            var service = scope.ServiceProvider.GetRequiredService<RegistrationService>();
            await service.DeleteExpiredChallengesAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // Normal host shutdown.
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to clean expired registration challenges");
        }
    }
}
