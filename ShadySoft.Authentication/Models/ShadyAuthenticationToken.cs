using System;
using System.Security.Claims;

namespace ShadySoft.Authentication.Models
{
    public class ShadyAuthenticationToken
    {
        public DateTime IssuedUtc { get; set; }
        public DateTime ExpiresUtc { get; set; }
        public ClaimsPrincipal Principal { get; set; }
        public DateTime PrincipalIssuedUtc { get; set; }
        public DateTime PrincipalExpiresUtc { get; set; }
        public bool IsPersistent { get; set; }

        public ShadyAuthenticationToken()
        {
        }

        public ShadyAuthenticationToken(ClaimsPrincipal principal, ShadyAuthenticationOptions options, bool isPersistent)
        {
            Principal = principal;
            IsPersistent = isPersistent;
            IssuedUtc = DateTime.UtcNow;
            ExpiresUtc = DateTime.UtcNow + (isPersistent ? options.PersistentExpireTimeSpan : options.RegularExpireTimeSpan);
            PrincipalIssuedUtc = DateTime.UtcNow;
            PrincipalExpiresUtc = DateTime.UtcNow + options.PrincipalExpireTimespan;
        }
    }
}
