using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace API_Identity.Models.Dtos.Requests;

public class GoogleSiginTokenRequestDto
{
    [Required]
    [JsonPropertyName("idToken")]
    public string IdToken { get; set; }
}