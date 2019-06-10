using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;
using ShadySoft.Authentication.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace ShadySoft.Authentication
{
    public class ShadyAuthenticationDataFormat : ISecureDataFormat<ShadyAuthenticationToken>
    {
        private readonly IDataProtector _protector;

        public ShadyAuthenticationDataFormat(IDataProtector dataProtector)
        {
            _protector = dataProtector;
        }

        public string Protect(ShadyAuthenticationToken data)
        {
            return Protect(data, null);
        }

        public string Protect(ShadyAuthenticationToken data, string purpose)
        {
            var protector = _protector;
            if (!string.IsNullOrWhiteSpace(purpose))
                protector = _protector.CreateProtector(purpose);

            var middleToken = new MiddleToken(data);

            return protector.Protect(JsonConvert.SerializeObject(middleToken));
        }

        public ShadyAuthenticationToken Unprotect(string protectedText)
        {
            return Unprotect(protectedText, null);
        }

        public ShadyAuthenticationToken Unprotect(string protectedText, string purpose)
        {
            var protector = _protector;
            if (!string.IsNullOrWhiteSpace(purpose))
                protector = _protector.CreateProtector(purpose);

            string decryptedTokenString;

            try
            {
                decryptedTokenString = protector.Unprotect(protectedText);
            }
            catch (CryptographicException)
            {
                return null;
            }

            if (string.IsNullOrWhiteSpace(decryptedTokenString))
                return null;

            MiddleToken middleToken;
            try
            {
                middleToken = JsonConvert.DeserializeObject<MiddleToken>(decryptedTokenString);
            }
            catch
            {
                return null;
            }

            return middleToken.ToShadyToken();
        }

        private class MiddleToken
        {
            public DateTime IssuedUtc { get; set; }
            public DateTime ExpriesUtc { get; set; }
            public byte[] PrincipalBytes { get; set; }
            public DateTime PrincipalIssuedUtc { get; set; }
            public DateTime PrincipalExpiresUtc { get; set; }
            public bool IsPersistent { get; set; }

            public MiddleToken()
            {
            }

            public MiddleToken(ShadyAuthenticationToken token)
            {
                MemoryStream outputStream = new MemoryStream();
                var writer = new BinaryWriter(outputStream);
                token.Principal.WriteTo(writer);
                PrincipalBytes = outputStream.ToArray();

                IssuedUtc = token.IssuedUtc;
                ExpriesUtc = token.ExpiresUtc;
                PrincipalIssuedUtc = token.PrincipalIssuedUtc;
                PrincipalExpiresUtc = token.PrincipalExpiresUtc;
                IsPersistent = token.IsPersistent;
            }

            public ShadyAuthenticationToken ToShadyToken()
            {
                MemoryStream inputStream = new MemoryStream(PrincipalBytes);
                var reader = new BinaryReader(inputStream);
                var principal = new ClaimsPrincipal(reader);

                return new ShadyAuthenticationToken
                {
                    Principal = principal,
                    IssuedUtc = IssuedUtc,
                    ExpiresUtc = ExpriesUtc,
                    PrincipalIssuedUtc = PrincipalIssuedUtc,
                    PrincipalExpiresUtc = PrincipalExpiresUtc,
                    IsPersistent = IsPersistent
                };
            }
        }
    }
}
