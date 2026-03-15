namespace OpenTOY.Emails.Views.Emails.ResetPassword;

public record ResetPasswordViewModel(string Email, string ServiceName, string ResetLink, int ExpiresInMinutes);