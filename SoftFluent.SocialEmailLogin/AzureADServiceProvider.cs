using System.Collections.Generic;
using System.Net;

namespace SoftFluent.SocialEmailLogin
{
    public class AzureADServiceProvider : AuthServiceProvider
    {
        public AzureADServiceProvider()
        {
            Protocol = AuthProtocol.OAuth20;
            UserLocationStorageType = UserLocationStorageType.State;

            UserAuthorizationUrl = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize";
            AccessTokenUrl = "https://login.microsoftonline.com/common/oauth2/v2.0/token";
            ProfileUrl = "https://graph.microsoft.com/v1.0/me";

            OAuth2AccessTokenMethod = "POST";
            Scope = "User.Read";
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
            if (data.ContainsKey("displayName"))
            {
                userData.Name = data["displayName"] as string;
            }

            if (data.ContainsKey("givenName"))
            {
                userData.FirstName = data["givenName"] as string;
            }
            if (data.ContainsKey("surname"))
            {
                userData.LastName = data["surname"] as string;
            }

            if (data.ContainsKey("mail"))
            {
                userData.Email = data["mail"] as string;
            }

            if (string.IsNullOrEmpty(userData.Email))
            {
                if (data.ContainsKey("userPrincipalName"))
                {
                    var userPrincipalName = data["userPrincipalName"] as string;
                    if (userPrincipalName?.Contains("@") == true)
                    {
                        userData.Email = userPrincipalName;
                    }
                }
            }

            return userData;
        }
    }
}
