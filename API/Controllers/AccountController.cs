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

namespace API.Controllers
{
    public class AccountController:BaseApiController
    {
        private readonly DataContext _context;
        public AccountController(DataContext context){
            _context =  context;
        }

        [HttpPost("register")]
        public async Task<ActionResult<AppUser>> Register([FromBody]RegisterDto _Data)
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

            
            return user;
        }

        private async Task<bool> isUserExists(string username)
        {
            return await _context.Users.AnyAsync(x=> x.UserName == username.ToLower());
        }

    }
}