using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Seguridad.Models
{
    public class UsuarioToken
    {
        public string Token { get; set; }
        public DateTime Expiracion { get; set; }
    }
}
