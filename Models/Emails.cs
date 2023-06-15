namespace UserAuth.Models
{
    public class Emails
    {
        public string To { get; set; }
        public string Subject { get; set; }
        public string Body { get; set; }
        public Emails(string to, string subject, string content)
        {
            To = to;
            Subject = subject;
            Body = content;
        }
    }
}
