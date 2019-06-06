using Microsoft.AspNetCore.Http;
using System;

namespace ShadySoft.Authentication.Extensions.Context
{
    public static class HttpContextExtensions
    {
        private const string ShadyAuthenticatedUser = "ShadyAuthenticatedUser";

        public static TUser GetAuthorizedUser<TUser>(this HttpContext context)
            where TUser : class
        {
            return (TUser)context.Items[ShadyAuthenticatedUser];
        }

        public static void StoreAuthorizedUser<TUser>(this HttpContext context, TUser user)
            where TUser : class
        {
            if (context.Items.ContainsKey(ShadyAuthenticatedUser))
                context.Items.Remove(ShadyAuthenticatedUser);

            context.Items.Add(ShadyAuthenticatedUser, user);
        }
    }
}
