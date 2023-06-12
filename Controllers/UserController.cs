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

namespace UserAuth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly AddDbcontext _authContext;
        public UserController(AddDbcontext addDbContext)
        {
            _authContext = addDbContext; 
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



            return Ok(new
            {
                Message = "Login feito com sucesso.",
                dbUser.Email,
                dbUser.UserName,
                dbUser.LastName,
                dbUser.FirstName,
                accesstoken = "",
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

        private string CheckPasswordStrength(string Password)
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

        private string CreateJwtToken(User userObj)
        {
            var jwtHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes("acesstoken");
            var identity = new ClaimsIdentity(new Claim[]
            {
                new Claim(ClaimTypes.Role, userObj.Role),
                new Claim(ClaimTypes.Name, $"{userObj.FirstName}{userObj.LastName}"),
            });
            var credentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = identity,
                Expires = DateTime.Now.AddDays(3),
                SigningCredentials = credentials,
            };
            var token = jwtHandler.CreateToken(tokenDescriptor);
            return jwtHandler.WriteToken(token);
        }

    }
}
