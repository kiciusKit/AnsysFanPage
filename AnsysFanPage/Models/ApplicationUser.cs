using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace AnsysFanPage.Models
{
    public class ApplicationUser : IdentityUser
    {
        public string NickName { get; set; }
    }

}
