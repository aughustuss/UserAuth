using MailKit.Net.Smtp;
using MimeKit;
using UserAuth.Models;

namespace UserAuth.Utility
{
    public class EmailService : IEmailService
    {
        private readonly IConfiguration _config;

        public EmailService(IConfiguration configuration)
        {
            _config = configuration;
        }

        public void SendEmail(Emails email)
        {
            var emailObj = new MimeMessage();
            var from = _config["EmailSettings: From"];
            emailObj.From.Add(new MailboxAddress("AD's Burguer", from));
            emailObj.To.Add(new MailboxAddress(email.To, email.To));
            emailObj.Subject = email.Subject;
            emailObj.Body = new TextPart(MimeKit.Text.TextFormat.Html)
            {
                Text = string.Format(email.Body)
            };
            using (var client = new SmtpClient())
            {
                try
                {
                    client.Connect(_config["EmailSettings: SmtpServer"], 465, true);
                    client.Authenticate(_config["EmailSettings: From"], _config["EmailSettings: Password"]);
                    client.Send(emailObj);
                } catch (Exception ex)
                {
                    throw;                  
                } finally
                {
                    client.Disconnect(true);
                    client.Dispose();
                }
            }
        }
    }
}
