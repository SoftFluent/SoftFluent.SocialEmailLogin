using System.Collections.Generic;
using System.Net;

namespace SoftFluent.SocialEmailLogin
{
    public class YammerServiceProvider : AuthServiceProvider
    {
        public YammerServiceProvider()
        {
            Protocol = AuthProtocol.OAuth20;
            UserLocationStorageType = UserLocationStorageType.State;
            UserAuthorizationUrl = "https://www.yammer.com/dialog/oauth";
            AccessTokenUrl = "https://www.yammer.com/oauth2/access_token.json";
            ProfileUrl = "https://www.yammer.com/api/v1/users/current.json";
        }

        protected override HttpWebRequest CreateGetOAuth20Request(string accessToken)
        {
            var request = (HttpWebRequest)WebRequest.Create(ProfileUrl);
            request.Headers.Add(HttpRequestHeader.Authorization, "Bearer " + accessToken);
            return request;
        }

        protected override UserData GetUserData(IDictionary<string, object> data)
        {
            if (data == null || data.Count == 0)
                return null;

            UserData userData = CreateUserData(data);
            if (data.ContainsKey("full_name"))
            {
                userData.Name = data["full_name"] as string;
            }

            if (data.ContainsKey("first_name"))
            {
                userData.FirstName = data["first_name"] as string;
            }

            if (data.ContainsKey("last_name"))
            {
                userData.LastName = data["last_name"] as string;
            }

            if (data.ContainsKey("email"))
            {
                userData.Email = data["email"] as string;
            }
            return userData;
        }
    }
}