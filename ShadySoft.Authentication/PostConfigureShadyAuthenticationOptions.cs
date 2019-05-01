using Microsoft.Extensions.Options;

namespace ShadySoft.Authentication
{
    public class PostConfigureShadyAuthenticationOptions : IPostConfigureOptions<ShadyAuthenticationOptions>
    {
        public void PostConfigure(string name, ShadyAuthenticationOptions options)
        {
        }
    }
}