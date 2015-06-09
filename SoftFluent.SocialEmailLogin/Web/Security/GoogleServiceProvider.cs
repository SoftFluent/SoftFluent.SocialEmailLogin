using CodeFluent.Runtime.Utilities;

namespace SoftFluent.SocialEmailLogin.Web.Security
{
    public class GoogleServiceProvider : AuthServiceProvider
    {
        public GoogleServiceProvider()
        {
            Protocol = AuthProtocol.OAuth20;
            UserAuthorizationUrl = "https://accounts.google.com/o/oauth2/auth";
            AccessTokenUrl = "https://www.googleapis.com/oauth2/v3/token";
            ProfileUrl = "https://www.googleapis.com/plus/v1/people/me/openIdConnect";
            OAuth2AccessTokenMethod = "POST";

            Scope = "email profile";
        }
    }
}
