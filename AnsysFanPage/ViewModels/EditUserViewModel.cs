using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace AnsysFanPage.ViewModels
{
    public class EditUserViewModel
    {
        public EditUserViewModel()
        {
            Claims = new List<string>();
            Roles = new List<string>();
        }
        
        [Required]
        [Remote(action: "IsNickNameInUse", controller: "Administration", AdditionalFields = "Id")]
        public string NickName { get; set; }
        public string Id { get; set; }
        public string UserName { get; set; }
        [Required]
        [EmailAddress]
        [Remote(action: "IsEmailInUse", controller: "Administration", AdditionalFields = "Id")]
        public string Email { get; set; }
        public IList<string> Claims { get; set; }
        public IList<string> Roles { get; set; }
    }
}
