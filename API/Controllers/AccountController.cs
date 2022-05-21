using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using API.Data;
using API.Entities;
using API.DTOs;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using API.Interfaces;

namespace API.Controllers
{
    public class AccountController:BaseApiController
    {
        private readonly DataContext _context;
        private readonly ITokenService _tokenService;
        public AccountController(DataContext context, ITokenService tokenService){
            _context =  context;
            _tokenService = tokenService;
        }

        [HttpPost("register")]
        public async Task<ActionResult<UserDto>> Register([FromBody]RegisterDto _Data)
        {
            if(await isUserExists(_Data.Username))
                return BadRequest("Username is taken."); 

            using var hmac = new HMACSHA512();
            
            var user = new AppUser
            {
                UserName = _Data.Username.ToLower(),
                PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(_Data.Password)),
                PasswordSalt=hmac.Key,
            };

            _context.Users.Add(user);
            await _context.SaveChangesAsync();
            
            // string body = await new StreamReader(Request.Body).ReadToEndAsync();

            return new UserDto{
                Username = user.UserName,
                Token  = _tokenService.CreateToken(user)
            };
        }

        [HttpPost("login")]
        public async Task<ActionResult<UserDto>> Login(LoginDto _Data)
        {
            var user = await _context.Users.SingleOrDefaultAsync(x=> x.UserName ==_Data.Username);
            if(user == null) return Unauthorized("Invalid username");

            using var hmac = new HMACSHA512(user.PasswordSalt);
            var computeHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(_Data.Password));
            for(int i=0; i<computeHash.Length; i++){
                if(computeHash[i]!= user.PasswordHash[i]) return Unauthorized("Invalid password");
            }

            return new UserDto{
                Username = user.UserName,
                Token  = _tokenService.CreateToken(user)
            };        }

        private async Task<bool> isUserExists(string username)
        {
            return await _context.Users.AnyAsync(x=> x.UserName == username.ToLower());
        }

    }
}