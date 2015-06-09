namespace SoftFluent.SocialEmailLogin.Web.Security
{
    public class MicrosoftServiceProvider : AuthServiceProvider
    {
        public MicrosoftServiceProvider()
        {
            Protocol = AuthProtocol.OAuth20;
            UserAuthorizationUrl = "https://login.live.com/oauth20_authorize.srf";
            AccessTokenUrl = "https://login.live.com/oauth20_token.srf";
            ProfileUrl = "https://apis.live.net/v5.0/me";

            //  http://stackoverflow.com/questions/9766771/using-live-connect-api-in-asp-net-to-retrieve-a-users-email-address
            Scope = "wl.emails";
        }
    }
}
