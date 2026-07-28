package management

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"mime"
	"net"
	"net/mail"
	"net/smtp"
	"strings"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/config"
)

type registrationMailer interface {
	Configured() bool
	SendVerificationCode(context.Context, string, string, string, int64) error
}

type smtpRegistrationMailer struct {
	config config.EmailVerificationConfig
}

func newSMTPRegistrationMailer(cfg config.EmailVerificationConfig) registrationMailer {
	return &smtpRegistrationMailer{config: cfg}
}

func (m *smtpRegistrationMailer) Configured() bool {
	if m == nil || !m.config.Enabled || strings.TrimSpace(m.config.SMTPHost) == "" ||
		strings.TrimSpace(m.config.FromAddress) == "" || m.config.SMTPPort <= 0 {
		return false
	}
	_, err := mail.ParseAddress(m.config.FromAddress)
	return err == nil
}

func (m *smtpRegistrationMailer) SendVerificationCode(
	ctx context.Context, email, username, code string, ttlSeconds int64,
) error {
	if !m.Configured() {
		return fmt.Errorf("registration mail is not configured")
	}
	recipient, err := mail.ParseAddress(email)
	if err != nil {
		return fmt.Errorf("invalid recipient: %w", err)
	}
	address := net.JoinHostPort(m.config.SMTPHost, fmt.Sprintf("%d", m.config.SMTPPort))
	dialer := &net.Dialer{Timeout: 8 * time.Second}
	var conn net.Conn
	if m.config.SMTPSSL {
		conn, err = tls.DialWithDialer(dialer, "tcp", address, &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: m.config.SMTPHost,
		})
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", address)
	}
	if err != nil {
		return fmt.Errorf("connect SMTP server: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	client, err := smtp.NewClient(conn, m.config.SMTPHost)
	if err != nil {
		return fmt.Errorf("start SMTP client: %w", err)
	}
	defer client.Close()
	if !m.config.SMTPSSL && (m.config.SMTPStartTLS || m.config.SMTPStartTLSRequired) {
		if advertised, _ := client.Extension("STARTTLS"); advertised {
			if err := client.StartTLS(&tls.Config{MinVersion: tls.VersionTLS12, ServerName: m.config.SMTPHost}); err != nil {
				return fmt.Errorf("start SMTP TLS: %w", err)
			}
		} else if m.config.SMTPStartTLSRequired {
			return fmt.Errorf("SMTP server does not advertise STARTTLS")
		}
	}
	if strings.TrimSpace(m.config.SMTPUsername) != "" {
		auth := smtp.PlainAuth("", m.config.SMTPUsername, m.config.SMTPPassword, m.config.SMTPHost)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("authenticate SMTP client: %w", err)
		}
	}
	from, _ := mail.ParseAddress(m.config.FromAddress)
	if err := client.Mail(from.Address); err != nil {
		return fmt.Errorf("set SMTP sender: %w", err)
	}
	if err := client.Rcpt(recipient.Address); err != nil {
		return fmt.Errorf("set SMTP recipient: %w", err)
	}
	writer, err := client.Data()
	if err != nil {
		return fmt.Errorf("open SMTP message: %w", err)
	}
	buffer := bufio.NewWriter(writer)
	fromLabel := from.Address
	if strings.TrimSpace(m.config.FromName) != "" {
		fromLabel = (&mail.Address{Name: m.config.FromName, Address: from.Address}).String()
	}
	minutes := (ttlSeconds + 59) / 60
	if minutes < 1 {
		minutes = 1
	}
	subject := mime.QEncoding.Encode("UTF-8", m.config.Subject)
	body := fmt.Sprintf("你好，%s：\r\n\r\n你的 specus 注册验证码是：%s\r\n\r\n验证码在 %d 分钟内有效，请勿转发给他人。\r\n如果不是你发起的注册，请忽略此邮件。\r\n", username, code, minutes)
	message := "From: " + fromLabel + "\r\n" +
		"To: " + recipient.String() + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/plain; charset=UTF-8\r\n" +
		"Content-Transfer-Encoding: 8bit\r\n\r\n" + body
	if _, err := buffer.WriteString(message); err != nil {
		_ = writer.Close()
		return fmt.Errorf("write SMTP message: %w", err)
	}
	if err := buffer.Flush(); err != nil {
		_ = writer.Close()
		return fmt.Errorf("flush SMTP message: %w", err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("finish SMTP message: %w", err)
	}
	return client.Quit()
}
