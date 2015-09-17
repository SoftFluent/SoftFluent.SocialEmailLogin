using System.Collections.Generic;
using System.Net;

namespace SoftFluent.SocialEmailLogin
{
    public class LinkedInServiceProvider : AuthServiceProvider
    {
        public LinkedInServiceProvider()
        {
            Protocol = AuthProtocol.OAuth20;
            UserLocationStorageType = UserLocationStorageType.State;
            UserAuthorizationUrl = "https://www.linkedin.com/uas/oauth2/authorization";
            AccessTokenUrl = "https://www.linkedin.com/uas/oauth2/accessToken";
            ProfileUrl = "https://api.linkedin.com/v1/people/~:(email-address,first-name,last-name)";

            Scope = "r_emailaddress r_basicprofile";
            State["token"] = "S0ftF1u3nt";
        }

        protected override HttpWebRequest CreateGetOAuth20Request(string accessToken)
        {
            return (HttpWebRequest)WebRequest.Create(ProfileUrl + "?format=json&oauth2_access_token=" + accessToken);
        }

        protected override UserData GetUserData(IDictionary<string, object> data)
        {
            if (data == null || data.Count == 0)
                return null;

            UserData userData = CreateUserData(data);
            if (data.ContainsKey("firstName"))
            {
                userData.FirstName = data["firstName"] as string;
            }

            if (data.ContainsKey("lastName"))
            {
                userData.LastName = data["lastName"] as string;
            }
            
            if (data.ContainsKey("emailAddress"))
            {
                userData.Email = data["emailAddress"] as string;
            }
            return userData;
        }
    }
}
