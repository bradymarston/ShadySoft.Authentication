using Microsoft.AspNetCore.DataProtection;
using Newtonsoft.Json;
using ShadySoft.Authentication.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace ShadySoft.Authentication
{
    public class TokenService
    {
        private readonly IDataProtectionProvider _protectionProvider;

        public TokenService(IDataProtectionProvider protectionProvider)
        {
            _protectionProvider = protectionProvider;
        }

        public ShadyAuthenticationToken DecodeTokenString(string tokenString)
        {
            string decryptedTokenString;

            try
            {
                var protector = _protectionProvider.CreateProtector("UserToken");
                decryptedTokenString = protector.Unprotect(tokenString);
            }
            catch (CryptographicException)
            {
                return null;
            }

            if (string.IsNullOrWhiteSpace(decryptedTokenString))
                return null;

            try
            {
                return JsonConvert.DeserializeObject<ShadyAuthenticationToken>(decryptedTokenString);
            }
            catch
            {
                return null;
            }
        }

        public string EncodeTokenString(ShadyAuthenticationToken token)
        {
            var protector = _protectionProvider.CreateProtector("UserToken");
            return protector.Protect(JsonConvert.SerializeObject(token));
        }
    }
}
