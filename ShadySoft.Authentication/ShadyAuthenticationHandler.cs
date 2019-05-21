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
        private readonly TokenService _tokenService;
        private readonly UserManager<TUser> _userManager;
        private readonly IUserClaimsPrincipalFactory<TUser> _principalFactory;

        public ShadyAuthenticationHandler(
            IOptionsMonitor<ShadyAuthenticationOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock,
            TokenService tokenService,
            UserManager<TUser> userManager,
            IUserClaimsPrincipalFactory<TUser> principalFactory)
            : base(options, logger, encoder, clock)
        {
            _tokenService = tokenService;
            _userManager = userManager;
            _principalFactory = principalFactory;
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (!Request.Headers.ContainsKey("Authorization"))
                return AuthenticateResult.NoResult();

            if (!AuthenticationHeaderValue.TryParse(Request.Headers["Authorization"], out AuthenticationHeaderValue headerValue))
            {
                return AuthenticateResult.NoResult();
            }

            if (headerValue.Scheme != ShadyAuthenticationDefaults.AuthenticationScheme)
                return AuthenticateResult.NoResult();

            var token = _tokenService.DecodeTokenString(headerValue.Parameter);
            if (token is null)
                return AuthenticateResult.Fail("Invalid authentication header");

            var user = await _userManager.FindByIdAsync(token.UserId);
            if (user is null)
                return AuthenticateResult.Fail("User in authentication header cannot be found");

            if (token.SecurityStamp != user.SecurityStamp)
                return AuthenticateResult.Fail("Token is no longer valid");

            var ticket = await BuildTicketAsync(user);

            Context.StoreAuthorizedUser(user);

            return AuthenticateResult.Success(ticket);
        }

        protected override async Task HandleSignInAsync(ClaimsPrincipal user, AuthenticationProperties properties)
        {
            var token = new ShadyAuthenticationToken
            {
                UserId = user.Claims.First(c => c.Type == ClaimTypes.NameIdentifier).Value,
                SecurityStamp = user.Claims.First(c => c.Type == "AspNet.Identity.SecurityStamp").Value,
                Issued = DateTime.UtcNow
            };

            var tokenString = _tokenService.EncodeTokenString(token);

            SetTokenHeaders(token.UserId, tokenString, properties.IsPersistent);
        }

        protected override Task HandleSignOutAsync(AuthenticationProperties properties)
        {
            throw new NotImplementedException();
        }

        private async Task<AuthenticationTicket> BuildTicketAsync(TUser user)
        {
            var principal = await _principalFactory.CreateAsync(user);
            return new AuthenticationTicket(principal, ShadyAuthenticationDefaults.AuthenticationScheme);
        }

        private void SetTokenHeaders(string userId, string tokenString, bool isPersistent)
        {
            Response.Headers.Add("access-token", tokenString);
            Response.Headers.Add("token-type", ShadyAuthenticationDefaults.AuthenticationScheme);
            Response.Headers.Add("persist-login", isPersistent.ToString());
            Response.Headers.Add("user-id", userId);
        }
    }
}