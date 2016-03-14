using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace SoftFluent.SocialEmailLogin
{
    public class YahooServiceProvider : AuthServiceProvider
    {
        public YahooServiceProvider()
        {
            Protocol = AuthProtocol.OpenIdOAuth;
            UserLocationStorageType = UserLocationStorageType.RedirectUri;
            DiscoveryUrl = "http://open.login.yahooapis.com/openid20/www.yahoo.com/xrds";
            OpenIdOAuthScope = "email,fullname,nickname";
        }

        protected override void SetOpenIdOAuthAttributes(IDictionary<string, string> headers)
        {
            headers.Add("openid.ax.type.fullname", "http://axschema.org/namePerson");
            headers.Add("openid.ax.type.nickname", "http://axschema.org/namePerson/friendly");
            base.SetOpenIdOAuthAttributes(headers);
        }

        protected override UserData GetUserData(HttpRequest httpRequest)
        {
            if (httpRequest == null)
                return null;

            var data = new Dictionary<string, object>();
            foreach (string key in httpRequest.QueryString.AllKeys.Where(key => key.StartsWith("openid.")))
            {
                data[key] = DecodeUrlParameter(httpRequest.QueryString[key]);
            }

            foreach (string key in httpRequest.Form.AllKeys.Where(key => key.StartsWith("openid.")))
            {
                data[key] = DecodeUrlParameter(httpRequest.Form[key]);
            }

            UserData userData = CreateUserData(data);
            userData.Email = data["openid.ax.value.email"] as string;
            userData.Name = data["openid.ax.value.nickname"] as string ?? data["openid.ax.value.fullname"] as string;
            return userData;
        }
    }
}
