// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

using System;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;
using System.Security.Claims;

namespace Owin.Security.Providers.Okta
{
    /// <summary>
    /// Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.
    /// </summary>
    public class OktaAuthenticatedContext : BaseContext
    {
        /// <summary>
        /// Initializes a <see cref="OktaAuthenticatedContext"/>
        /// </summary>
        /// <param name="context">The OWIN environment</param>
        /// <param name="user">The JSON-serialized user</param>
        /// <param name="accessToken">Okta Access token</param>
        public OktaAuthenticatedContext(IOwinContext context, string idToken, string accessToken)
            : base(context)
        {
            IdToken = idToken;
            AccessToken = accessToken;
            Id = "placeholder";
            Name = "placename";
        }

        public string IdToken { get; private set; }

        /// <summary>
        /// Gets the Okta OAuth access token
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        /// Gets the Okta user ID
        /// </summary>
        public string Id { get; private set; }

        /// <summary>
        /// Get the name of the user
        /// </summary>
        public string Name { get; private set; }

        /// <summary>
        /// Gets the <see cref="ClaimsIdentity"/> representing the user
        /// </summary>
        public ClaimsIdentity Identity { get; set; }

        /// <summary>
        /// Gets or sets a property bag for common authentication properties
        /// </summary>
        public AuthenticationProperties Properties { get; set; }

        private static string TryGetValue(JObject user, string propertyName)
        {
            JToken value;
            return user.TryGetValue(propertyName, out value) ? value.ToString() : null;
        }
    }
}