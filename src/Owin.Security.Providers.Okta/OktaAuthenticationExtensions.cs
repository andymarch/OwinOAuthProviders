using System;

namespace Owin.Security.Providers.Okta
{
    public static class OktaAuthenticationExtensions
    {
        public static IAppBuilder UseOktaAuthentication(this IAppBuilder app, OktaAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException(nameof(app));
            if (options == null)
                throw new ArgumentNullException(nameof(options));

            app.Use(typeof(OktaAuthenticationMiddleware), app, options);

            return app;
        }

        public static IAppBuilder UseOktaAuthentication(this IAppBuilder app, string clientId, string clientSecret)
        {
            if (string.IsNullOrEmpty(clientId))
                throw new ArgumentNullException(nameof(clientId));
            if (string.IsNullOrEmpty(clientSecret))
                throw new ArgumentNullException(nameof(clientSecret));
            
            return app.UseOktaAuthentication(new OktaAuthenticationOptions
            {
                ClientId = clientId,
                ClientSecret = clientSecret
            });
        }
    }
}