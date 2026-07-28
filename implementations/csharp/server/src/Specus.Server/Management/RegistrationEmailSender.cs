using MailKit.Security;
using Microsoft.Extensions.Options;
using MimeKit;
using MimeKit.Text;
using Specus.Server.Configuration;
using Specus.Server.Security;
using System.Net.Mail;
using MailKitSmtpClient = MailKit.Net.Smtp.SmtpClient;

namespace Specus.Server.Management;

public interface IRegistrationEmailSender
{
    bool Configured { get; }
    Task SendVerificationCodeAsync(string email, string username, string code, long ttlSeconds,
        CancellationToken cancellationToken = default);
}

public sealed class SmtpRegistrationEmailSender : IRegistrationEmailSender
{
    private readonly AuthOptions _options;
    private readonly ILogger<SmtpRegistrationEmailSender> _logger;

    public SmtpRegistrationEmailSender(IOptions<AuthOptions> options,
        ILogger<SmtpRegistrationEmailSender> logger)
    {
        _options = options.Value;
        _logger = logger;
    }

    public bool Configured => _options.EmailVerificationEnabled
        && !string.IsNullOrWhiteSpace(_options.SmtpHost)
        && _options.SmtpPort is > 0 and <= 65535
        && MailAddress.TryCreate(_options.EmailFromAddress, out _)
        && (!_options.SmtpAuth
            || (!string.IsNullOrWhiteSpace(_options.SmtpUsername)
                && !string.IsNullOrWhiteSpace(_options.SmtpPassword)));

    public async Task SendVerificationCodeAsync(string email, string username, string code,
        long ttlSeconds, CancellationToken cancellationToken = default)
    {
        if (!Configured)
        {
            throw new AuthenticationDependencyUnavailableException("注册邮件服务未配置");
        }

        var minutes = Math.Max(1, (ttlSeconds + 59) / 60);
        var message = new MimeMessage
        {
            Subject = _options.EmailSubject,
            Body = new TextPart(TextFormat.Plain)
            {
                Text = $"你好，{username}：\n\n"
                    + $"你的 specus 注册验证码是：{code}\n\n"
                    + $"验证码在 {minutes} 分钟内有效，请勿转发给他人。\n"
                    + "如果不是你发起的注册，请忽略此邮件。\n",
            },
        };
        message.From.Add(new MailboxAddress(_options.EmailFromName.Trim(),
            _options.EmailFromAddress.Trim()));
        message.To.Add(MailboxAddress.Parse(email));

        using var client = new MailKitSmtpClient();
        try
        {
            await client.ConnectAsync(_options.SmtpHost.Trim(), _options.SmtpPort,
                    ResolveSocketOptions(), cancellationToken)
                .ConfigureAwait(false);
            if (_options.SmtpAuth)
            {
                await client.AuthenticateAsync(_options.SmtpUsername.Trim(), _options.SmtpPassword,
                        cancellationToken)
                    .ConfigureAwait(false);
            }
            await client.SendAsync(message, cancellationToken).ConfigureAwait(false);
            await client.DisconnectAsync(true, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to send registration verification email");
            throw new AuthenticationDependencyUnavailableException("验证码邮件发送失败，请稍后重试");
        }
    }

    private SecureSocketOptions ResolveSocketOptions()
    {
        if (_options.SmtpSsl)
        {
            return SecureSocketOptions.SslOnConnect;
        }
        if (_options.SmtpStartTlsRequired)
        {
            return SecureSocketOptions.StartTls;
        }
        return _options.SmtpStartTls
            ? SecureSocketOptions.StartTlsWhenAvailable
            : SecureSocketOptions.None;
    }
}
