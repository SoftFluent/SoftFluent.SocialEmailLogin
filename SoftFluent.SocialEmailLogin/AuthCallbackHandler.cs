using System;
using System.Web;
using SoftFluent.SocialEmailLogin.Configuration;
using System.Collections.Generic;
using System.Net;
using System.Web.Security;
using SoftFluent.SocialEmailLogin.Utilities;

namespace SoftFluent.SocialEmailLogin
{
    public class AuthCallbackHandler : IHttpHandler
    {
        public bool IsReusable
        {
            get
            {
                return true;
            }
        }

        protected virtual AuthServiceProvider GetServiceProvider(string providerName)
        {
            return SocialEmailLoginSection.Current.Authentication.GetServiceProvider(providerName);
        }

        public virtual void ProcessRequest(HttpContext context)
        {
            if (context == null)
                throw new ArgumentNullException("context");

            var state = ReadStateQueryParameter(context);
            string providerName = GetValue(context, state, AuthServiceProvider.ProviderParameter) as string;
            if (providerName == null)
                return;

            AuthServiceProvider provider = GetServiceProvider(providerName);
            if (provider == null)
                return;

            AuthLoginOptions loginOptions = ConvertUtilities.ChangeType(GetValue(context, state, AuthServiceProvider.OptionsParameter), AuthLoginOptions.None);
            UserData userData = provider.GetUserData(context);
            if (userData == null)
                return;

            Authenticate(context, provider, loginOptions, userData);
        }

        protected virtual bool Authenticate(HttpContext context, AuthServiceProvider provider, AuthLoginOptions options, UserData userData)
        {
            return true;
        }

        protected virtual void RedirectSuccess(HttpContext context)
        {
            if (context == null) throw new ArgumentNullException(nameof(context));

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
                url = AuthServiceProvider.GetAbsoluteApplicationPath();
            }
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
            FormsAuthenticationTicket ticket = new FormsAuthenticationTicket(2, userName, DateTime.Now, DateTime.Now.Add(FormsAuthentication.Timeout), createPersistentCookie, userData, FormsAuthentication.FormsCookiePath);
            string encryptedTicket = FormsAuthentication.Encrypt(ticket);
            if (encryptedTicket == null || encryptedTicket.Length < 1)
                throw new AuthException("OA0006: Failed to encrypt ticket.");

            HttpCookie cookie = new HttpCookie(FormsAuthentication.FormsCookieName, encryptedTicket);
            cookie.HttpOnly = httpOnly;
            cookie.Path = FormsAuthentication.FormsCookiePath;

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
            if (context == null) throw new ArgumentNullException(nameof(context));

            try
            {
                string st = context.Request.QueryString["state"];
                if (!string.IsNullOrWhiteSpace(st))
                {
                    return Extensions.JsonDeserialize(HttpUtility.UrlDecode(st));
                }
            }
            catch
            {
            }

            return null;
        }
    }
}
