namespace SoftFluent.SocialEmailLogin.Web.Security
{
    public class YahooServiceProvider : AuthServiceProvider
    {
        public YahooServiceProvider()
        {
            Protocol = AuthProtocol.OpenIdOAuth;
            DiscoveryUrl = "http://open.login.yahooapis.com/openid20/www.yahoo.com/xrds";
        }
    }
}
