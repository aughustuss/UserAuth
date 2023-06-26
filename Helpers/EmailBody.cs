using Microsoft.EntityFrameworkCore.Storage.ValueConversion.Internal;

namespace UserAuth.Helpers
{
    public static class EmailBody
    {
        public static string EmailStringBody(string email, string emailToken)
        {
            return $@"
<html>
<head>
</head>
<body>
<div stlye=""display: flex; flex-direction: column; justify-content: center; align-content: center; align-items: center; gap: 20px;"">
<h1>Redefina a sua senha</h1>
<p>Clique no botão abaixo para ir à página de redefinição de senha.</p>
<a  href=""https://projeto-foods-aughustuss.vercel.app/reset?email={email}&code={emailToken}"" target=""_blank"" style=""padding: 10px 20px; background: #e7b630; border-radius: 3px; width: 50%; text-align: center; text-decoration: none; color: black;"">Redefinir senha</a>
</div>
</body>
</html>";
        }
    }
}
