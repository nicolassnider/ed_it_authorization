using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Seguridad.Models;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Seguridad.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [EnableCors("PermitirApiRequest")]
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    public class CuentaController : ControllerBase
    {
        private readonly UserManager<UsuarioAplicacion> _userManager;
        private readonly SignInManager<UsuarioAplicacion> _signInManager;
        private readonly IConfiguration _configuration;

        public CuentaController(
            UserManager<UsuarioAplicacion> userManager,
            SignInManager<UsuarioAplicacion> signInManager,
            IConfiguration configuration)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _configuration = configuration;
        }

        [HttpPost("Crear")]
        public async Task<ActionResult<UsuarioToken>> CrearUsuario([FromBody] UsuarioInfo model)
        {
            var user = new UsuarioAplicacion { UserName = model.Email, Email = model.Email };
            var result = await _userManager.CreateAsync(user, model.Password);

            if (result.Succeeded)
            {
                return CrearToken(model, new List<string>());
            }
            else
            {
                return BadRequest("Usuario o Contrasena inválidos");
            }
        }

        [HttpPost("Ingresar")]
        public async Task<ActionResult<UsuarioToken>> Ingresar([FromBody] UsuarioInfo userInfo)
        {
            var result = await _signInManager.PasswordSignInAsync(userInfo.Email, userInfo.Password, isPersistent: false, lockoutOnFailure: false);
            if (result.Succeeded)
            {
                var usuario = await _userManager.FindByEmailAsync(userInfo.Email);
                var roles = await _userManager.GetRolesAsync(usuario);
                return CrearToken(userInfo, roles);
            }
            else
            {
                ModelState.AddModelError(string.Empty, "Ingreso inválido");
                return BadRequest(ModelState);
            }
        }

        private UsuarioToken CrearToken(UsuarioInfo userInfo, IList<string> roles)
        {
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.UniqueName, userInfo.Email),
                new Claim("miValor","loQueYoQuiera"),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            foreach (var rol in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, rol));
            }
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:key"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            //t de expiración de token
            var expiration = DateTime.Now.AddYears(1);

            JwtSecurityToken token = new JwtSecurityToken(
                issuer: null,
                audience: null,
                claims: claims,
                expires: expiration,
                signingCredentials: creds
                );

            return new UsuarioToken()
            {
                Token = new JwtSecurityTokenHandler().WriteToken(token),
                Expiracion = expiration
            };

        }
    }
}




