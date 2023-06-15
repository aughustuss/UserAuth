using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using UserAuth.Context;
using UserAuth.Models;
using UserAuth.Helpers;
using System.Text;
using System.Text.RegularExpressions;
using System.IdentityModel.Tokens.Jwt;
using System;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Authorization;
using System.Security.Cryptography;
using UserAuth.Models.Dto;
using UserAuth.Migrations;
using UserAuth.Utility;

namespace UserAuth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly AddDbcontext _authContext;
        private readonly IConfiguration _config;
        private readonly IEmailService _emailService;
        public UserController(AddDbcontext addDbContext, IConfiguration configuration, IEmailService emailService)
        {
            _authContext = addDbContext;
            _config = configuration;
            _emailService = emailService;
        }
        [HttpPost("authenticate")]
        public async Task<IActionResult> Authenticate([FromBody] User userObj)
        {
            if (userObj == null)
                return BadRequest();
            var dbUser = await _authContext.Users.FirstOrDefaultAsync(x => x.Email == userObj.Email);
            if (dbUser == null)
                return NotFound(new {Message = "Email inválido."});

            if (!Hasher.VerifyPassword(userObj.Password, dbUser.Password))
                return BadRequest(new { Message = "Senha inválida." });

            dbUser.Token = CreateJwt(dbUser);
            var accessToken = dbUser.Token;
            var refreshToken = CreateJwtRefresh();
            dbUser.RefreshToken = refreshToken;
            dbUser.TokenExpiration = DateTime.UtcNow.AddDays(5);
            await _authContext.SaveChangesAsync();

            return Ok(new TokenApiDto()
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken
            });
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] User userObj)
        {
            var emailExists = await _authContext.Users.FirstOrDefaultAsync(x => x.Email == userObj.Email);
            var userNameExists = await _authContext.Users.FirstOrDefaultAsync(y => y.UserName == userObj.UserName);

            if (await CheckUserNameExistsAsync(userObj.UserName))
                return BadRequest(new {Message = "Nome de usuário já está em uso."});
            if (await CheckEmailExistsAsync(userObj.Email))
                return BadRequest(new { Message = "Email já está em uso." });

            var passStrength = CheckPasswordStrength(userObj.Password);
            if (!string.IsNullOrEmpty(passStrength))
                return BadRequest(new { Message = passStrength.ToString()});

            if (userObj == null)
                return BadRequest("Não é possível cadastrar sem os dados.");
            userObj.Password = Hasher.HashPassword(userObj.Password);
            userObj.Role = "User";
            userObj.Token = "";
            await _authContext.Users.AddAsync(userObj);
            await _authContext.SaveChangesAsync();
            return Ok(new
            {
                Message = "Registro feito com sucesso."
            });
        }

        private async Task<bool> CheckUserNameExistsAsync(string UserName) 
        { 
            return await _authContext.Users.AnyAsync(x => x.UserName == UserName);
        }

        private async Task<bool> CheckEmailExistsAsync(string Email)
        {
            return await _authContext.Users.AnyAsync(x => x.Email == Email);
        }

        private static string CheckPasswordStrength(string Password)
        {
            StringBuilder sb = new StringBuilder();
            if(Password.Length < 8)
                sb.Append("Tamanho mínimo deve ser de 8 caractéres."+Environment.NewLine);

            if (!(Regex.IsMatch(Password, "[a-z]") && Regex.IsMatch(Password, "[A-Z]") && Regex.IsMatch(Password, "[0-9]")))
                sb.Append("Senha deve conter uma letra maiúscula, uma minúscula e um número." + Environment.NewLine);

            if (!(Regex.IsMatch(Password, "[<,>,@,!,#,$,%,^,&,*,(,),_,+,\\[,\\],{,},?,:,;,|,',\\,.,/,~,`,-,=]")))
                sb.Append("Senha deve conter pelo menos um caractére especial." + Environment.NewLine);

            return sb.ToString();
        }

        private static string CreateJwt(User user)
        {
            var securitykey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("h1tQCpuDMroijuG56kAt72346TYGBNSHRY1276FHCNSKAJRYSBC"));
            var credentials = new SigningCredentials(securitykey, SecurityAlgorithms.HmacSha256);
            var claims = new ClaimsIdentity(new Claim[]
            {
                new Claim(ClaimTypes.Name, $"{user.FirstName} {user.LastName}"),
                new Claim(ClaimTypes.Role, user.Role),
            });
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = claims,
                Expires = DateTime.UtcNow.AddMinutes(5),
                SigningCredentials = credentials,
            };
            var jwtHandler = new JwtSecurityTokenHandler();
            var token = jwtHandler.CreateToken(tokenDescriptor);
            return jwtHandler.WriteToken(token);
        }

        private string CreateJwtRefresh()
        {
            var tokenBytes = RandomNumberGenerator.GetBytes(64);
            var refreshToken = Convert.ToBase64String(tokenBytes);

            var tokenPresents = _authContext.Users.Any(a => a.RefreshToken == refreshToken);

            if (tokenPresents)
                return CreateJwtRefresh();

            return refreshToken;
        }

        private ClaimsPrincipal GetPrincipalFromToken(string token)
        {
            var key = Encoding.ASCII.GetBytes("h1tQCpuDMroijuG56kAt72346TYGBNSHRY1276FHCNSKAJRYSBC");
            var refreshTokenParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateLifetime = false
            };
            var refreshTokenHandler = new JwtSecurityTokenHandler();
            SecurityToken securityToken;
            var principal = refreshTokenHandler.ValidateToken(token, refreshTokenParameters, out securityToken);
            var jwtSecurityToken = securityToken as JwtSecurityToken;
            if (jwtSecurityToken == null || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                throw new SecurityTokenException("Token inválido...");
            return principal;
        }

        [HttpPost("refresh")]
        
        public async Task<IActionResult> RefreshToken(TokenApiDto tokenApi)
        {
            if (tokenApi == null)
                return BadRequest("Requisição inválida. ");
            string accessToken = tokenApi.AccessToken;
            string refreshToken = tokenApi.RefreshToken;
            var getPrincipal = GetPrincipalFromToken(accessToken);
            var username = getPrincipal.Identity.Name;
            var user = await _authContext.Users.FirstOrDefaultAsync(u => u.UserName == username);
            if (user == null || user.RefreshToken != refreshToken || user.TokenExpiration <= DateTime.UtcNow)
                return BadRequest("Token inválido na requisição.");
            var newAccessToken = CreateJwt(user);
            var newRefreshToken = CreateJwtRefresh();
            user.RefreshToken = newRefreshToken;
            await _authContext.SaveChangesAsync();
            return Ok(new TokenApiDto()
            {
                AccessToken = newAccessToken,
                RefreshToken = newRefreshToken
            });
        }

        [HttpPost("send-reset-email/{email}")]
        public async Task<IActionResult> SendEmail(string email)
        {
            var user = await _authContext.Users.FirstOrDefaultAsync(a => a.Email == email);
            if (user is null)
            {
                return NotFound(new
                {
                    StatusCode = 404,
                    Message = "Email não encontrado."
                });
            }
            var tokenBytes = RandomNumberGenerator.GetBytes(64);
            var emailToken = Convert.ToBase64String(tokenBytes);
            user.ResetPasswordToken = emailToken;
            user.ResetPasswordExpiration = DateTime.UtcNow.AddMinutes(15);
            string from = _config["EmailSettings: From"];
            var emailObj = new Emails(email, "Redefinição de Senha", EmailBody.EmailStringBody(email, emailToken));
            _emailService.SendEmail(emailObj);
            _authContext.Entry(user).State = EntityState.Modified;
            await _authContext.SaveChangesAsync();
            return Ok(new
            {
                Status = 200,
                Message = "Email enviado."
            });
        }

        [HttpPost("reset-email")]
        public async Task<IActionResult> ResetPassword(ResetPasswordDto resetPasswordDto)
        {
            var newToken = resetPasswordDto.EmailToken.Replace(" ", "+");
            var user = await _authContext.Users.AsNoTracking().FirstOrDefaultAsync(u => u.Email == resetPasswordDto.Email);
            if (user == null)
            {
                return NotFound(new
                {
                    StatusCode = 404,
                    Message = "Usuário não existe..."
                }); 
            }
            var tokenCode = user.ResetPasswordToken;
            DateTime emailTokenExpirity = user.ResetPasswordExpiration;
            if (tokenCode != resetPasswordDto.EmailToken || emailTokenExpirity < DateTime.UtcNow)
            {
                return BadRequest(new
                {
                    StatusCode = 400,
                    Message = "Token expirado ou link inválido."
                });
            }
            user.Password = Hasher.HashPassword(resetPasswordDto.NewPassword);
            _authContext.Entry(user).State = EntityState.Modified;
            await _authContext.SaveChangesAsync();
            return Ok(new
            {
                StatusCode = 200,
                Message = "Senha redefinida com sucesso."
            });
            
        }

    }
}
