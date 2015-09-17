using System;
using System.Collections.Generic;
using System.Net;

namespace SoftFluent.SocialEmailLogin
{
    // https://msdn.microsoft.com/en-us/library/azure/dn645542.aspx
    public class Office365ServiceProvider : AuthServiceProvider
    {
        // http://blogs.msdn.com/b/besidethepoint/archive/2012/10/23/getting-started-with-azure-active-directory.aspx
        private const string AzureDirectoryAppId = "00000002-0000-0000-c000-000000000000";

        public Office365ServiceProvider()
        {
            Protocol = AuthProtocol.OAuth20;
            UserLocationStorageType = UserLocationStorageType.State;

            // Url that contains the tenant id does not allow user from other domains to log in
            //UserAuthorizationUrl = "https://login.microsoftonline.com/<tenant_id>/oauth2/authorize";
            //AccessTokenUrl = "https://login.microsoftonline.com/<tenant_id>/oauth2/token";
            UserAuthorizationUrl = "https://login.microsoftonline.com/common/oauth2/authorize";
            AccessTokenUrl = "https://login.microsoftonline.com/common/oauth2/token";

            ProfileUrl = "https://graph.windows.net/me?api-version=1.5";

            //State[ProviderParameter] = "Office365";
            OAuth2AccessTokenMethod = "POST";
            Scope = "openid email";
        }

        protected override HttpWebRequest CreateGetOAuth20Request(string accessToken)
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(ProfileUrl);
            request.Headers.Add(HttpRequestHeader.Authorization, "Bearer " + accessToken);
            return request;
        }

        protected override void OnAfterCreateAccessTokenOAuth20Headers(IDictionary<string, string> headers)
        {
            if (headers != null)
            {
                // redirect_uri => remove querystring so we match the declared redirect uri
                string redirectUri = headers["redirect_uri"];
                if (redirectUri != null)
                {
                    int indexOf = redirectUri.IndexOf("?", StringComparison.Ordinal);
                    if (indexOf > 0)
                    {
                        redirectUri = redirectUri.Substring(0, indexOf);
                        headers["redirect_uri"] = redirectUri;
                    }
                }

                // add resource identifier
                headers["resource"] = AzureDirectoryAppId;
                headers["response_mode"] = "query";
            }

            base.OnAfterCreateAccessTokenOAuth20Headers(headers);
        }

        protected override void OnAfterCreateLoginOAuth20Headers(IDictionary<string, string> headers)
        {
            if (headers != null)
            {
                headers["resource"] = AzureDirectoryAppId;
                headers["nonce"] = BuildNonce();
                headers["response_mode"] = "query";
                if (LoginOptions.HasFlag(AuthLoginOptions.RegisterApplication))
                {
                    headers["prompt"] = "admin_consent";
                }
            }

            base.OnAfterCreateLoginOAuth20Headers(headers);
        }

        protected override UserData GetUserData(IDictionary<string, object> data)
        {
            if (data == null || data.Count == 0)
                return null;

            UserData userData = CreateUserData(data);
            if (data.ContainsKey("displayName"))
            {
                userData.Name = data["displayName"] as string;
            }

            if (string.IsNullOrWhiteSpace(userData.Name))
            {
                if (data.ContainsKey("givenName"))
                {
                    userData.FirstName = data["givenName"] as string;
                }
                if (data.ContainsKey("surname"))
                {
                    userData.LastName = data["surname"] as string;
                }
            }

            if (data.ContainsKey("mail"))
            {
                userData.Email = data["mail"] as string;
            }
            return userData;
        }
    }
}
