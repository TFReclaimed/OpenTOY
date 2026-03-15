using System.ComponentModel.DataAnnotations;

namespace OpenTOY.Options;

[OptionsSection("PasswordResetSettings")]
public class PasswordResetOptions
{
    [Url]
    public string ResetPageBaseUrl { get; set; } = string.Empty;
    [Range(1, 120)]
    public int TokenLifetimeMinutes { get; set; }
}