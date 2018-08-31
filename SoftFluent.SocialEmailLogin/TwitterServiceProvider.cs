using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Web;
using SoftFluent.SocialEmailLogin.Utilities;

namespace SoftFluent.SocialEmailLogin
{
    public class TwitterServiceProvider : AuthServiceProvider
    {
        public TwitterServiceProvider()
        {
            Protocol = AuthProtocol.OAuth10a;
            UserLocationStorageType = UserLocationStorageType.RedirectUri;
            RequestTokenUrl = "https://api.twitter.com/oauth/request_token";
            UserAuthorizationUrl = "https://api.twitter.com/oauth/authenticate";
            AccessTokenUrl = "https://api.twitter.com/oauth/access_token";
            FakeEmailDomain = "twitter.socialemaillogin.com";
        }

        public override UserData GetUserData(HttpContext context)
        {
            if (context == null)
                throw new ArgumentNullException(nameof(context));

            string method = "POST";

            var headers = new Dictionary<string, string>
            {
                ["oauth_consumer_key"] = ConsumerKey,
                ["oauth_signature_method"] = "HMAC-SHA1",
                ["oauth_timestamp"] = BuildOAuthTimestamp(),
                ["oauth_nonce"] = BuildNonce(),
                ["oauth_version"] = "1.0",
                ["oauth_token"] = context.Request["oauth_token"],
                ["oauth_verifier"] = context.Request["oauth_verifier"]
            };
            headers["oauth_signature"] = EncodeParameter(SignOAuthRequest(method, AccessTokenUrl, headers, null));

            var request = (HttpWebRequest)WebRequest.Create(AccessTokenUrl);
            request.Headers.Add("Authorization", "OAuth " + SerializeOAuthHeaders(headers, method));
            request.Method = method;

            try
            {
                using (var response = (HttpWebResponse)request.GetResponse())
                {
                    using (var stream = response.GetResponseStream())
                    {
                        using (var reader = new StreamReader(stream))
                        {
                            IDictionary<string, object> data = new Dictionary<string, object>();
                            UserData userData = CreateUserData(data);
                            userData.Name = Extensions.GetQueryStringParameter(reader.ReadToEnd(), "screen_name", (string)null);
                            return userData;
                        }
                    }
                }
            }
            catch (WebException we)
            {
                if (we.Response != null)
                {
                    string text;
                    using (var reader = new StreamReader(we.Response.GetResponseStream()))
                    {
                        text = reader.ReadToEnd();
                    }

                    if (string.IsNullOrEmpty(text))
                        throw;

                    throw new AuthException("OA0002: An OAuth error has occured. " + text, we);
                }

                throw new AuthException("OA0011: Unable to retrieve the user's screen_name.");
            }
        }
    }
}
