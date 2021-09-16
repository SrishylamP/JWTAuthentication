using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace JWTAuthentication.Models
{
    public class ResponseMessage
    {
        public int? NoOfAttempts { get; set; }
        public bool IsSuccess { get; set; }
        public string message { get; set; }
        public string email { get; set; }
        public int? RoleId { get; set; }
        public bool? IsFirstTimeUser { get; set; }
        public int? UserId { get; set; }
        public string? EmployeeId { get; set; }
        public DateTime? Expires { get; set; }
        public string Token { get; set; }


    }
}
