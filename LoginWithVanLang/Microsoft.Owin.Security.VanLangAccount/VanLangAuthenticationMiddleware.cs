﻿// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net;
using System.Net.Http;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security.DataHandler;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.Infrastructure;
using Owin;

namespace Microsoft.Owin.Security.VanLangAccount
{
	/// <summary>
	/// OWIN middleware for authenticating users using VanLang
	/// </summary>
	[SuppressMessage("Microsoft.Design", "CA1001:TypesThatOwnDisposableFieldsShouldBeDisposable", Justification = "Middleware is not disposable.")]
	public class VanLangAuthenticationMiddleware : AuthenticationMiddleware<VanLangAuthenticationOptions>
	{
		private readonly ILogger _logger;
		private readonly HttpClient _httpClient;

		/// <summary>
		/// Initializes a <see cref="VanLangAuthenticationMiddleware"/>
		/// </summary>
		/// <param name="next">The next middleware in the OWIN pipeline to invoke</param>
		/// <param name="app">The OWIN application</param>
		/// <param name="options">Configuration options for the middleware</param>
		public VanLangAuthenticationMiddleware(
			OwinMiddleware next,
			IAppBuilder app,
			VanLangAuthenticationOptions options)
			: base(next, options)
		{
			_logger = app.CreateLogger<VanLangAuthenticationMiddleware>();

			if (Options.Provider == null)
			{
				Options.Provider = new VanLangAuthenticationProvider();
			}
			if (Options.StateDataFormat == null)
			{
				IDataProtector dataProtector = app.CreateDataProtector(
					typeof(VanLangAuthenticationMiddleware).FullName,
					Options.AuthenticationType, "v1");
				Options.StateDataFormat = new PropertiesDataFormat(dataProtector);
			}
			if (String.IsNullOrEmpty(Options.SignInAsAuthenticationType))
			{
				Options.SignInAsAuthenticationType = app.GetDefaultSignInAsAuthenticationType();
			}
			ServicePointManager.ServerCertificateValidationCallback += (sender, cert, chain, sslPolicyErrors) => true;
			_httpClient = new HttpClient();//ResolveHttpMessageHandler(Options));
			_httpClient.Timeout = TimeSpan.FromSeconds(60);
			_httpClient.MaxResponseContentBufferSize = 1024 * 1024 * 10; // 10 MB
		}

		/// <summary>
		/// Provides the <see cref="AuthenticationHandler"/> object for processing authentication-related requests.
		/// </summary>
		/// <returns>An <see cref="AuthenticationHandler"/> configured with the <see cref="VanLangAuthenticationOptions"/> supplied to the constructor.</returns>
		protected override AuthenticationHandler<VanLangAuthenticationOptions> CreateHandler()
		{
			return new VanLangAuthenticationHandler(_httpClient, _logger);
		}

		[SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Justification = "Managed by caller")]
		private static HttpMessageHandler ResolveHttpMessageHandler(VanLangAuthenticationOptions options)
		{
			HttpMessageHandler handler = options.BackchannelHttpHandler;//?? new WebRequestHandler();

			// If they provided a validator, apply it or fail.
			if (options.BackchannelCertificateValidator != null)
			{
				// Set the cert validate callback
				//                var webRequestHandler = handler as WebRequestHandler;
				//                if (webRequestHandler == null)
				//                {
				//                    throw new InvalidOperationException(Resources.Exception_ValidatorHandlerMismatch);
				//                }
				//                webRequestHandler.ServerCertificateValidationCallback = options.BackchannelCertificateValidator.Validate;
			}

			return handler;
		}
	}
}
