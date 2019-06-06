using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using System;

namespace ShadySoft.Authentication.Extensions.DependencyInjection
{
    public static class AuthenticationExtensions
    {
        public static AuthenticationBuilder AddShady<TUser>(this AuthenticationBuilder builder)
            where TUser : IdentityUser
        {
            return AddShady<TUser>(builder, ShadyAuthenticationDefaults.AuthenticationScheme, _ => { });
        }

        public static AuthenticationBuilder AddShady<TUser>(this AuthenticationBuilder builder, string authenticationScheme)
            where TUser : IdentityUser
        {
            return AddShady<TUser>(builder, authenticationScheme, _ => { });
        }

        public static AuthenticationBuilder AddShady<TUser>(this AuthenticationBuilder builder, Action<ShadyAuthenticationOptions> configureOptions)
            where TUser : IdentityUser
        {
            return AddShady<TUser>(builder, ShadyAuthenticationDefaults.AuthenticationScheme, configureOptions);
        }

        public static AuthenticationBuilder AddShady<TUser>(this AuthenticationBuilder builder, string authenticationScheme, Action<ShadyAuthenticationOptions> configureOptions)
            where TUser : IdentityUser
        {
            builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<ShadyAuthenticationOptions>, PostConfigureShadyAuthenticationOptions>());
            builder.Services.AddOptions<ShadyAuthenticationOptions>(authenticationScheme);
            return builder.AddScheme<ShadyAuthenticationOptions, ShadyAuthenticationHandler<TUser>>(authenticationScheme, null, configureOptions);
        }

        public static AuthenticationBuilder AddShadyAuthentication<TUser>(this IServiceCollection services)
            where TUser : IdentityUser
        {
            services.AddScoped<TokenService>();

            return services.AddAuthentication(ShadyAuthenticationDefaults.AuthenticationScheme)
                .AddShady<TUser>()
                .AddShady<TUser>(IdentityConstants.ApplicationScheme)
                .AddShady<TUser>(IdentityConstants.ExternalScheme)
                .AddShady<TUser>(IdentityConstants.TwoFactorUserIdScheme);
        }
    }
}
