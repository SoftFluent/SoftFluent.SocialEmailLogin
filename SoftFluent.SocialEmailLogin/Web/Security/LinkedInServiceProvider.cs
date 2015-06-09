using System.IO;
using System.Net;

namespace SoftFluent.SocialEmailLogin.Web.Security
{
    public class LinkedInServiceProvider : AuthServiceProvider
    {
        public LinkedInServiceProvider()
        {
            Protocol = AuthProtocol.OAuth20;
            UserAuthorizationUrl = "https://www.linkedin.com/uas/oauth2/authorization";
            AccessTokenUrl = "https://www.linkedin.com/uas/oauth2/accessToken";
            ProfileUrl = "https://api.linkedin.com/v1/people/~/email-address";

            Scope = "r_emailaddress";
            State = "s0C1aLeMa1Ll0g1N";
        }

        protected override string GetEmail(string accessToken)
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(ProfileUrl + "?format=json&oauth2_access_token=" + accessToken);

            try
            {
                using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
                {
                    using (Stream stream = response.GetResponseStream())
                    {
                        using (StreamReader reader = new StreamReader(stream))
                        {
                            return reader.ReadToEnd().Replace("\"", "");
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
                }
                if (string.IsNullOrEmpty(text))
                    throw;

                throw new AuthException("OA0005: An OAuth error has occured. " + text, we);
            }
        }
    }
}
