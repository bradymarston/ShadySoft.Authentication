using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using ShadySoft.Authentication.Models;
using System;

namespace ShadySoft.Authentication
{
    public class ShadyAuthenticationOptions : AuthenticationSchemeOptions
    {
        public ShadyAuthenticationOptions()
        {
            SlidingExpiration = true;
            RegularExpireTimeSpan = TimeSpan.FromDays(2);
            PersistentExpireTimeSpan = TimeSpan.FromDays(182);
            PrincipalExpireTimespan = TimeSpan.FromMinutes(5);
        }

        /// <summary>
        /// If set this will be used by the SahdyAuthenticationHandler for data protection.
        /// </summary>
        public IDataProtectionProvider DataProtectionProvider { get; set; }

        /// <summary>
        /// The SlidingExpiration is set to true to instruct the handler to re-issue a new cookie with a new
        /// expiration time any time it processes a request which is more than halfway through the expiration window.
        /// </summary>
        public bool SlidingExpiration { get; set; }


        /// <summary>
        /// Controls how much time the authentication token will remain valid from the point it is created for a regular login.
        /// </summary>
        public TimeSpan RegularExpireTimeSpan { get; set; }

        /// <summary>
        /// Controls how much time the authentication token will remain valid from the point it is created for a persistent login.
        /// </summary>
        public TimeSpan PersistentExpireTimeSpan { get; set; }

        /// <summary>
        /// Controls how much time the claims principal will remain valid from the point it is created.
        /// If expired, the ticket will be refreshed as long as the containing token has not expired.
        /// </summary>
        public TimeSpan PrincipalExpireTimespan { get; set; }

        /// <summary>
        /// The ShadyAuthenticationTokenDataFormat is used to protect and unprotect the identity and other properties which are stored in the
        /// cookie value. If not provided one will be created using <see cref="DataProtectionProvider"/>.
        /// </summary>
        public ISecureDataFormat<ShadyAuthenticationToken> ShadyAuthenticationTokenDataFormat { get; set; }

    }
}