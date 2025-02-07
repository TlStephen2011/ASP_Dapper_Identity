using System.Text.Json.Serialization;

namespace API_Common.Models;

public class GenericResponseDto<T>
{
    [JsonPropertyName("data")]
    public T Data { get; set; }
    [JsonPropertyName("message")]
    public string Message { get; set; }
}

public class GenericResponseDto
{
    [JsonPropertyName("message")]
    public string Message { get; set; }
}