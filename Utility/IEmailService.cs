using UserAuth.Models;

namespace UserAuth.Utility
{
    public interface IEmailService
    {
        void SendEmail(Emails email);
    }
}
