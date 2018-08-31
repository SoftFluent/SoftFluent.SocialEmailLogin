using System;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Web;
using System.Web.Security;
using SoftFluent.SocialEmailLogin.Configuration;
using SoftFluent.SocialEmailLogin.Utilities;

namespace SoftFluent.SocialEmailLogin
{
    public class AuthCallbackHandler : IHttpHandler
    {
        public bool IsReusable => true;

        protected virtual AuthServiceProvider GetServiceProvider(string providerName)
        {
            return GetAuthenticationElement().GetServiceProvider(providerName);
        }

        protected virtual AuthenticationElement GetAuthenticationElement()
        {
            return SocialEmailLoginSection.Current.Authentication;
        }

        public virtual void ProcessRequest(HttpContext context)
        {
            if (context == null)
                throw new ArgumentNullException(nameof(context));

            var state = ReadStateQueryParameter(context);
            if (!(GetValue(context, state, AuthServiceProvider.ProviderParameter) is string providerName))
                return;

            AuthenticationElement authenticationElement = GetAuthenticationElement();
            AuthServiceProvider provider = GetServiceProvider(providerName);
            if (provider == null)
                return;

            AuthLoginOptions loginOptions = ConvertUtilities.ChangeType(GetValue(context, state, AuthServiceProvider.OptionsParameter), AuthLoginOptions.None);

            int attempt = 0;
            UserData userData = null;
            while (attempt < authenticationElement.MaximumRetryCount)
            {
                try
                {
                    userData = provider.GetUserData(context);
                    break;
                }
                catch (Exception ex)
                {
                    if (!OnGetUserDataError(context, ex, attempt))
                        break;

                    attempt++;
                    if (authenticationElement.RetryInterval > 0)
                    {
                        Thread.Sleep(authenticationElement.RetryInterval);
                    }
                }
            }

            if (userData == null)
            {
                Authenticate(context, provider, loginOptions);
            }
            else
            {
                Authenticate(context, provider, loginOptions, userData);
            }
        }

        protected virtual bool OnGetUserDataError(HttpContext context, Exception ex, int attempt)
        {
            if (ex is WebException)
                return true;

            return false;
        }

        protected virtual bool Authenticate(HttpContext context, AuthServiceProvider provider, AuthLoginOptions options)
        {
            return true;
        }

        protected virtual bool Authenticate(HttpContext context, AuthServiceProvider provider, AuthLoginOptions options, UserData userData)
        {
            return true;
        }

        protected virtual void RedirectSuccess(HttpContext context)
        {
            if (context == null)
                throw new ArgumentNullException(nameof(context));

            string url = null;
            var state = ReadStateQueryParameter(context);
            if (state != null && state.ContainsKey(AuthServiceProvider.UrlParameter))
            {
                url = state[AuthServiceProvider.UrlParameter] as string;
            }
            else
            {
                url = context.Request[AuthServiceProvider.UrlParameter].Nullify(trim: true);
            }

            if (string.IsNullOrEmpty(url))
            {
                if (GetValue(context, state, AuthServiceProvider.ProviderParameter) is string providerName)
                {
                    AuthenticationElement authenticationElement = GetAuthenticationElement();
                    AuthServiceProvider provider = GetServiceProvider(providerName);
                    if (provider != null)
                    {
                        url = provider.SuccessUrl;
                    }
                }
            }

            if (string.IsNullOrEmpty(url))
            {
                url = AuthServiceProvider.GetAbsoluteApplicationPath();
            }

            url = HttpUtility.UrlDecode(url);

            context.Response.Redirect(url, false);
        }

        protected virtual void RedirectUnauthorized(HttpContext context, bool allowRedirect)
        {
            context.Response.StatusDescription = "Forbidden.";
            context.Response.StatusCode = (int)HttpStatusCode.Forbidden;
            context.Response.End();
        }

        protected virtual HttpCookie GetAuthCookie(string userName, bool createPersistentCookie, bool httpOnly, string userData)
        {
            var ticket = new FormsAuthenticationTicket(2, userName, DateTime.Now, DateTime.Now.Add(FormsAuthentication.Timeout), createPersistentCookie, userData, FormsAuthentication.FormsCookiePath);
            string encryptedTicket = FormsAuthentication.Encrypt(ticket);
            if (string.IsNullOrEmpty(encryptedTicket))
                throw new AuthException("OA0006: Failed to encrypt ticket.");

            var cookie = new HttpCookie(FormsAuthentication.FormsCookieName, encryptedTicket)
            {
                HttpOnly = httpOnly,
                Path = FormsAuthentication.FormsCookiePath
            };

            if (FormsAuthentication.RequireSSL)
            {
                cookie.Secure = true;
            }

            if (FormsAuthentication.CookieDomain != null)
            {
                cookie.Domain = FormsAuthentication.CookieDomain;
            }

            if (ticket.IsPersistent)
            {
                cookie.Expires = ticket.Expiration;
            }
            return cookie;
        }

        protected virtual object GetValue(HttpContext context, IDictionary<string, object> state, string parameterName)
        {
            object value = context.Request[parameterName].Nullify(trim: true);
            if (value == null && state != null)
            {
                if (state.ContainsKey(parameterName))
                {
                    value = state[parameterName];
                }
            }
            return value;
        }

        protected virtual IDictionary<string, object> ReadStateQueryParameter(HttpContext context)
        {
            if (context == null)
                throw new ArgumentNullException(nameof(context));

            try
            {
                string st = context.Request.QueryString["state"];
                if (!string.IsNullOrWhiteSpace(st))
                    return Extensions.JsonDeserialize(HttpUtility.UrlDecode(st));
            }
            catch
            {
            }

            return null;
        }
    }
}