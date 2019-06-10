using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ShadySoft.Authentication.Extensions.Context;
using ShadySoft.Authentication.Models;
using System;
using System.Linq;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace ShadySoft.Authentication
{
    public class ShadyAuthenticationHandler<TUser> : SignInAuthenticationHandler<ShadyAuthenticationOptions>
        where TUser : IdentityUser
    {
        private readonly UserManager<TUser> _userManager;
        private readonly IUserClaimsPrincipalFactory<TUser> _principalFactory;

        public ShadyAuthenticationHandler(
            IOptionsMonitor<ShadyAuthenticationOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock,
            UserManager<TUser> userManager,
            IUserClaimsPrincipalFactory<TUser> principalFactory)
            : base(options, logger, encoder, clock)
        {
            _userManager = userManager;
            _principalFactory = principalFactory;
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            var refreshedToken = false;

            if (!Request.Headers.ContainsKey("Authorization"))
                return AuthenticateResult.NoResult();

            if (!AuthenticationHeaderValue.TryParse(Request.Headers["Authorization"], out AuthenticationHeaderValue headerValue))
            {
                return AuthenticateResult.NoResult();
            }

            if (headerValue.Scheme != ShadyAuthenticationDefaults.AuthenticationScheme)
                return AuthenticateResult.NoResult();

            var token = Options.ShadyAuthenticationTokenDataFormat.Unprotect(headerValue.Parameter);
            if (token is null)
                return AuthenticateResult.Fail("Invalid authentication header");

            if (token.ExpiresUtc < DateTime.UtcNow)
                return AuthenticateResult.Fail("Token is expired.");

            if (token.ExpiresUtc - DateTime.UtcNow < DateTime.UtcNow - token.IssuedUtc && Options.SlidingExpiration)
            {
                RefreshTokenExpirations(token);
                refreshedToken = true;
            }

            if (token.PrincipalExpiresUtc < DateTime.UtcNow)
            {
                try
                {
                    await RebuildPrincipleAsync(token);
                }
                catch (Exception e)
                {
                    return AuthenticateResult.Fail(e);
                }

                refreshedToken = true;
            }

            if (refreshedToken)
                SetTokenHeaders(token);

            var ticket = await BuildTicketAsync(token.Principal, token);

            return AuthenticateResult.Success(ticket);
        }

        protected override async Task HandleSignInAsync(ClaimsPrincipal user, AuthenticationProperties properties)
        {
            SetTokenHeaders(new ShadyAuthenticationToken(user, Options, properties.IsPersistent));
        }

        protected override async Task HandleSignOutAsync(AuthenticationProperties properties)
        {
            var userId = Context.User?.FindFirstValue(ClaimTypes.NameIdentifier);

            if (userId == null)
                return;

            var user = await _userManager.FindByIdAsync(userId);

            if (user == null)
                return;

            await _userManager.UpdateSecurityStampAsync(user);
        }

        private async Task<AuthenticationTicket> BuildTicketAsync(ClaimsPrincipal principal, ShadyAuthenticationToken token)
        {
            var properties = new AuthenticationProperties
            {
                IsPersistent = token.IsPersistent,
                IssuedUtc = token.IssuedUtc,
                AllowRefresh = Options.SlidingExpiration
            };
            return new AuthenticationTicket(principal, properties, ShadyAuthenticationDefaults.AuthenticationScheme);
        }

        private void SetTokenHeaders(ShadyAuthenticationToken token)
        {
            Response.Headers.Add("access-token", Options.ShadyAuthenticationTokenDataFormat.Protect(token));
            Response.Headers.Add("token-type", ShadyAuthenticationDefaults.AuthenticationScheme);
            Response.Headers.Add("persist-login", token.IsPersistent.ToString());
            Response.Headers.Add("user-id", token.Principal.FindFirstValue(ClaimTypes.NameIdentifier));
        }

        private void RefreshTokenExpirations(ShadyAuthenticationToken token)
        {
            var validPeriod = token.ExpiresUtc - token.IssuedUtc;
            token.IssuedUtc = DateTime.UtcNow;
            token.ExpiresUtc = DateTime.UtcNow + validPeriod;
        }

        private async Task RebuildPrincipleAsync(ShadyAuthenticationToken token)
        {
            var tokenUserId = token.Principal.FindFirstValue(ClaimTypes.NameIdentifier);
            var user = await _userManager.FindByIdAsync(tokenUserId);
            if (user is null)
                throw new Exception("User in principal could not be found");

            var principalSecurityStamp = token.Principal.FindFirstValue("AspNet.Identity.SecurityStamp");
            if (principalSecurityStamp != user.SecurityStamp)
                throw new Exception("User's security stamp has changed since principal was created");

            token.Principal = await _principalFactory.CreateAsync(user);

            var validPeriod = token.PrincipalExpiresUtc - token.PrincipalIssuedUtc;
            token.PrincipalIssuedUtc = DateTime.UtcNow;
            token.PrincipalExpiresUtc = DateTime.UtcNow + validPeriod;
        }
    }
}