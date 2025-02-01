namespace API_Identity.Models;

public class ApplicationUser
{
    public Guid Id { get; set; }
    public string UserName { get; set; }
    public string PasswordHash { get; set; }
}
