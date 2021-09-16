using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using JWTAuthentication.Data;
using JWTAuthentication.Models;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace JWTAuthentication.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [EnableCors("AllowOrigin")]
    public class AuthenticateController : ControllerBase
    {
        private readonly PMSDbContext dbContext;
        public IConfiguration _configuration;

        public AuthenticateController(PMSDbContext dbContext, IConfiguration configuration)
        {
            this.dbContext = dbContext;
            _configuration = configuration;
        }


        [HttpPost]
        [Route("Login")]
        public async Task<ResponseMessage> Login([FromBody] LoginModel model)
        {
            var resObj = new ResponseMessage();
            var user = await dbContext.Users.FirstOrDefaultAsync(e => e.Email == model.Email && e.Password == CreateMD5(model.Password) && e.IsActive);
            if (user != null)
            {
                resObj.IsSuccess = true;
                resObj.message = Constants.LOGINSUCCESSFULL + " " + user.FirstName + " " + user.LastName;
                resObj.NoOfAttempts = 0;
                resObj.RoleId = user.RoleId;
                resObj.email = user.Email;
                resObj.IsFirstTimeUser = user.IsFirstTimeUser;
                resObj.UserId = user.UserId;
                resObj.EmployeeId = user.EmployeeId;

                //Update db
                user.NoOfWrongAttempts = 0;
                await dbContext.SaveChangesAsync();

                var userRole = await dbContext.UserRoles.FirstOrDefaultAsync(e => e.RoleId == user.RoleId);
                var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.FirstName+user.LastName),
                    new Claim(ClaimTypes.Email, user.Email),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    new Claim(ClaimTypes.Role, userRole.RoleName),
                };

                var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));

                var token = new JwtSecurityToken(
                    issuer: _configuration["JWT:ValidIssuer"],
                    audience: _configuration["JWT:ValidAudience"],
                    expires: DateTime.Now.AddMinutes(30),
                    claims: authClaims,
                    signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
                    );
                
                resObj.Token = new JwtSecurityTokenHandler().WriteToken(token);
                resObj.Expires = token.ValidTo;
                return resObj;
            }
            else
            {
                var userExist = await dbContext.Users.Where(e => e.Email == model.Email).FirstOrDefaultAsync();
                if (userExist != null && userExist.IsActive)
                {
                    if (userExist.NoOfWrongAttempts < 2)
                    {
                        userExist.NoOfWrongAttempts++;
                        resObj.message = Constants.InvalidLoginCredentials;
                    }
                    else
                    {
                        userExist.NoOfWrongAttempts++;
                        userExist.IsActive = false;
                        resObj.message = Constants.LoginUserLocked;
                    }

                }
                else if (userExist == null)
                {
                    resObj.message = Constants.LoginUserLocked;
                }
                else
                    resObj.message = Constants.LoginUserLocked;

                resObj.IsSuccess = false;
                resObj.NoOfAttempts = userExist != null ? userExist.NoOfWrongAttempts : 0;
                await dbContext.SaveChangesAsync();

                return resObj;

            }
            //return Unauthorized();
        }
        public static string CreateMD5(string input)
        {
            // Use input string to calculate MD5 hash
            using (System.Security.Cryptography.MD5 md5 = System.Security.Cryptography.MD5.Create())
            {
                byte[] inputBytes = Encoding.UTF8.GetBytes(input);
                byte[] hashBytes = md5.ComputeHash(inputBytes);

                // Convert the byte array to hexadecimal string
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < hashBytes.Length; i++)
                {
                    sb.Append(hashBytes[i].ToString("X2"));
                }
                return sb.ToString();
            }
        }
    }
}
