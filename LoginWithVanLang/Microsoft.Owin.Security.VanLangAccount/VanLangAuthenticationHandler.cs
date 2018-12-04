﻿// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Owin.Helpers;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json.Linq;

namespace Microsoft.Owin.Security.VanLangAccount
{
	internal class VanLangAuthenticationHandler : AuthenticationHandler<VanLangAuthenticationOptions>
	{
		private const string XmlSchemaString = "http://www.w3.org/2001/XMLSchema#string";

		private readonly ILogger _logger;
		private readonly HttpClient _httpClient;

		public VanLangAuthenticationHandler(HttpClient httpClient, ILogger logger)
		{
			_httpClient = httpClient;
			_logger = logger;
		}

		protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
		{
			AuthenticationProperties properties = null;

			try
			{
				string code = null;
				string state = null;

				IReadableStringCollection query = Request.Query;

				IList<string> values = query.GetValues("error");
				if (values != null && values.Count >= 1)
				{
					_logger.WriteVerbose("Remote server returned an error: " + Request.QueryString);
				}

				values = query.GetValues("code");
				if (values != null && values.Count == 1)
				{
					code = values[0];
				}
				values = query.GetValues("state");
				if (values != null && values.Count == 1)
				{
					state = values[0];
				}

				properties = Options.StateDataFormat.Unprotect(state);
				if (properties == null)
				{
					return null;
				}

				if (code == null)
				{
					// Null if the remote server returns an error.
					return new AuthenticationTicket(null, properties);
				}

				string requestPrefix = Request.Scheme + "://" + Request.Host;
				string redirectUri = requestPrefix + Request.PathBase + Options.CallbackPath;

				var formContent = new FormUrlEncodedContent(new[]
				{
					new KeyValuePair<string, string>("code", Uri.EscapeDataString(code))
				});

				HttpResponseMessage tokenResponse = await _httpClient.PostAsync(Options.UserInformationEndpoint, formContent, Request.CallCancelled);
				tokenResponse.EnsureSuccessStatusCode();
				string user = await tokenResponse.Content.ReadAsStringAsync();
				JObject response = JObject.Parse(user);

				string accessToken = response.Value<string>("access_token");

				if (string.IsNullOrWhiteSpace(accessToken))
				{
					_logger.WriteWarning("Access token was not found");
					return new AuthenticationTicket(null, properties);
				}

				var email = response.Value<string>("Email");
				var defaultUserName = response.Value<string>("DefaultUserName");

				var context = new VanLangAuthenticatedContext(Context);
				context.Identity = new ClaimsIdentity(
					Options.AuthenticationType,
					ClaimsIdentity.DefaultNameClaimType,
					ClaimsIdentity.DefaultRoleClaimType);
				context.Identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, accessToken, XmlSchemaString, Options.AuthenticationType));
				if (!string.IsNullOrEmpty(defaultUserName))
				{
					context.Identity.AddClaim(new Claim(ClaimsIdentity.DefaultNameClaimType, defaultUserName, XmlSchemaString, Options.AuthenticationType));
				}
				if (!string.IsNullOrEmpty(email))
				{
					context.Identity.AddClaim(new Claim(ClaimTypes.Email, email, XmlSchemaString, Options.AuthenticationType));
				}
				context.Properties = properties;

				await Options.Provider.Authenticated(context);

				return new AuthenticationTicket(context.Identity, context.Properties);
			}
			catch (Exception ex)
			{
				_logger.WriteError("Authentication failed", ex);
				return new AuthenticationTicket(null, properties);
			}
		}

		protected override Task ApplyResponseChallengeAsync()
		{
			if (Response.StatusCode != 401)
			{
				return Task.FromResult<object>(null);
			}

			AuthenticationResponseChallenge challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);

			if (challenge != null)
			{
				string baseUri =
					Request.Scheme +
					Uri.SchemeDelimiter +
					Request.Host +
					Request.PathBase;

				string currentUri =
					baseUri +
					Request.Path +
					Request.QueryString;

				string redirectUri =
					baseUri +
					Options.CallbackPath;

				AuthenticationProperties properties = challenge.Properties;
				if (string.IsNullOrEmpty(properties.RedirectUri))
				{
					properties.RedirectUri = currentUri;
				}

				string state = Options.StateDataFormat.Protect(properties);

				string authorizationEndpoint = Options.AuthorizationEndpoint +
						"?redirect_uri=" + Uri.EscapeDataString(redirectUri) +
						"&state=" + Uri.EscapeDataString(state);

				var redirectContext = new VanLangApplyRedirectContext(
					Context, Options,
					properties, authorizationEndpoint);
				//Options.Provider.ApplyRedirect(redirectContext);
				Context.Response.Redirect(authorizationEndpoint);
			}

			return Task.FromResult<object>(null);
		}

		public override async Task<bool> InvokeAsync()
		{
			return await InvokeReplyPathAsync();
		}

		private async Task<bool> InvokeReplyPathAsync()
		{
			if (Options.CallbackPath.HasValue && Options.CallbackPath == Request.Path)
			{
				// TODO: error responses

				AuthenticationTicket ticket = await AuthenticateAsync();
				if (ticket == null)
				{
					_logger.WriteWarning("Invalid return state, unable to redirect.");
					Response.StatusCode = 500;
					return true;
				}

				var context = new VanLangReturnEndpointContext(Context, ticket);
				context.SignInAsAuthenticationType = Options.SignInAsAuthenticationType;
				context.RedirectUri = ticket.Properties.RedirectUri;

				await Options.Provider.ReturnEndpoint(context);

				if (context.SignInAsAuthenticationType != null &&
					context.Identity != null)
				{
					ClaimsIdentity grantIdentity = context.Identity;
					if (!string.Equals(grantIdentity.AuthenticationType, context.SignInAsAuthenticationType, StringComparison.Ordinal))
					{
						grantIdentity = new ClaimsIdentity(grantIdentity.Claims, context.SignInAsAuthenticationType, grantIdentity.NameClaimType, grantIdentity.RoleClaimType);
					}
					Context.Authentication.SignIn(context.Properties, grantIdentity);
				}

				if (!context.IsRequestCompleted && context.RedirectUri != null)
				{
					string redirectUri = context.RedirectUri;
					if (context.Identity == null)
					{
						// add a redirect hint that sign-in failed in some way
						redirectUri = WebUtilities.AddQueryString(redirectUri, "error", "access_denied");
					}
					Response.Redirect(redirectUri);
					context.RequestCompleted();
				}

				return context.IsRequestCompleted;
			}
			return false;
		}
	}
}
