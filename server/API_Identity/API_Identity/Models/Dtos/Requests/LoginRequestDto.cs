using System.Text.Json.Serialization;

namespace API_Identity.Models.Dtos.Requests;

public class LoginRequestDto
{
    [JsonPropertyName("username")]
    public string Username { get; set; }
    [JsonPropertyName("password")]
    public string Password { get; set; }
}