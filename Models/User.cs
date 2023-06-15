using System.ComponentModel.DataAnnotations;

namespace UserAuth.Models
{
    public class User
    {
        [Key]
        public  int Id { get; set; }
        public string FirstName { get; set; } = string.Empty;
        public string LastName { get; set; } = string.Empty;
        public string UserName { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
        public string Token { get; set; } = string.Empty;
        public string Role { get; set; } = string.Empty;
        public string RefreshToken { get; set; } = string.Empty;
        public DateTime TokenExpiration { get; set; }
        public string? ResetPasswordToken { get; set; }
        public DateTime ResetPasswordExpiration { get; set; }
    }
}
