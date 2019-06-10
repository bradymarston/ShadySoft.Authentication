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
            return AddShadyAuthentication<TUser>(services, _ => { });
        }

        public static AuthenticationBuilder AddShadyAuthentication<TUser>(this IServiceCollection services, Action<ShadyAuthenticationOptions> configureOptions)
            where TUser : IdentityUser
        {
            return services.AddAuthentication(ShadyAuthenticationDefaults.AuthenticationScheme)
                .AddShady<TUser>(configureOptions)
                .ForwardScheme(IdentityConstants.ApplicationScheme, ShadyAuthenticationDefaults.AuthenticationScheme)
                .ForwardScheme(IdentityConstants.ExternalScheme, ShadyAuthenticationDefaults.AuthenticationScheme)
                .ForwardScheme(IdentityConstants.TwoFactorUserIdScheme, ShadyAuthenticationDefaults.AuthenticationScheme);
        }

        public static AuthenticationBuilder ForwardScheme(this AuthenticationBuilder authBuilder, string schemeToForward, string targetScheme)
        {
            return authBuilder.AddPolicyScheme(schemeToForward, schemeToForward, options =>
            {
                options.ForwardDefault = targetScheme;
            });
        }
    }
}