using SoftFluent.SocialEmailLogin.Utilities;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Web;

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
                throw new ArgumentNullException("context");

            string method = "POST";

            Dictionary<string, string> headers = new Dictionary<string, string>();
            headers["oauth_consumer_key"] = ConsumerKey;
            headers["oauth_signature_method"] = "HMAC-SHA1";
            headers["oauth_timestamp"] = BuildOAuthTimestamp();
            headers["oauth_nonce"] = BuildNonce();
            headers["oauth_version"] = "1.0";
            headers["oauth_token"] = context.Request["oauth_token"];
            headers["oauth_verifier"] = context.Request["oauth_verifier"];
            headers["oauth_signature"] = EncodeParameter(SignOAuthRequest(method, AccessTokenUrl, headers, null));

            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(AccessTokenUrl);
            request.Headers.Add("Authorization", "OAuth " + SerializeOAuthHeaders(headers, method));
            request.Method = method;

            try
            {
                using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
                {
                    using (Stream stream = response.GetResponseStream())
                    {
                        using (StreamReader reader = new StreamReader(stream))
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
                string text = null;
                if (we.Response != null)
                {
                    using (StreamReader reader = new StreamReader(we.Response.GetResponseStream()))
                    {
                        text = reader.ReadToEnd();
                    }

                    if (string.IsNullOrEmpty(text))
                        throw;

                    throw new AuthException("OA0002: An OAuth error has occured. " + text, we);
                }

                throw new AuthException("OA0006: Unable to retrieve the user's screen_name.");
            }
        }
    }
}
