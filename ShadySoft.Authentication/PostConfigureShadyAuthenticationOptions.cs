using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;

namespace ShadySoft.Authentication
{
    public class PostConfigureShadyAuthenticationOptions : IPostConfigureOptions<ShadyAuthenticationOptions>
    {
        private readonly IDataProtectionProvider _dp;

        public PostConfigureShadyAuthenticationOptions(IDataProtectionProvider dp)
        {
            _dp = dp;
        }

        public void PostConfigure(string name, ShadyAuthenticationOptions options)
        {
            options.DataProtectionProvider = options.DataProtectionProvider ?? _dp;

            if (options.ShadyAuthenticationTokenDataFormat == null)

            {

                // Note: the purpose for the data protector must remain fixed for interop to work.

                var dataProtector = options.DataProtectionProvider.CreateProtector("ShadySoft.Authentication", name, "v2");

                options.ShadyAuthenticationTokenDataFormat = new ShadyAuthenticationDataFormat(dataProtector);

            }

        }
    }
}