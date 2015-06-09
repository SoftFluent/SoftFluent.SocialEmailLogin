namespace SoftFluent.SocialEmailLogin.Web.Security
{
    public class FacebookServiceProvider : AuthServiceProvider
    {
        public FacebookServiceProvider()
        {
            Protocol = AuthProtocol.OAuth20;
            UserAuthorizationUrl = "https://www.facebook.com/dialog/oauth";
            AccessTokenUrl = "https://graph.facebook.com/oauth/access_token";
            ProfileUrl = "https://graph.facebook.com/me";

            // http://stackoverflow.com/questions/5625532/facebook-c-sharp-sdk-get-users-email
            Scope = "email,public_profile";
        }
    }
}
