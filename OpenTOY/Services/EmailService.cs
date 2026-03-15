using MailKit.Net.Smtp;
using Microsoft.Extensions.Options;
using MimeKit;
using MimeKit.Text;
using Mjml.Net;
using OpenTOY.Emails.Services;
using OpenTOY.Options;

namespace OpenTOY.Services;

public interface IEmailService
{
    Task SendEmailAsync<TModel>(string to, string subject, string viewName, TModel model);
}

public class EmailService : IEmailService
{
    private readonly IRazorViewToStringRenderer _razorViewToStringRenderer;

    private readonly IMjmlRenderer _mjmlRenderer;

    private readonly IOptions<EmailOptions> _emailOptions;

    public EmailService(IRazorViewToStringRenderer razorViewToStringRenderer, IMjmlRenderer mjmlRenderer,
        IOptions<EmailOptions> emailOptions)
    {
        _razorViewToStringRenderer = razorViewToStringRenderer;
        _mjmlRenderer = mjmlRenderer;
        _emailOptions = emailOptions;
    }

    public async Task SendEmailAsync<TModel>(string to, string subject, string viewName, TModel model)
    {
        var viewHtml = await _razorViewToStringRenderer.RenderViewToStringAsync(viewName, model);
        var (html, _) = await _mjmlRenderer.RenderAsync(viewHtml);

        var message = new MimeMessage();
        message.From.Add(new MailboxAddress(_emailOptions.Value.FromName, _emailOptions.Value.FromEmail));
        message.To.Add(new MailboxAddress(null, to));
        message.Subject = subject;
        message.Body = new TextPart(TextFormat.Html)
        {
            Text = html
        };

        using var smtp = new SmtpClient();
        await smtp.ConnectAsync(_emailOptions.Value.SmtpHost, _emailOptions.Value.SmtpPort);
        await smtp.AuthenticateAsync(_emailOptions.Value.SmtpUser, _emailOptions.Value.SmtpPass);
        await smtp.SendAsync(message);
        await smtp.DisconnectAsync(true);
    }
}