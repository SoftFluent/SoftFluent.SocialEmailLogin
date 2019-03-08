using System.Collections.Generic;

namespace SoftFluent.SocialEmailLogin
{
    public class GoogleServiceProvider : AuthServiceProvider
    {
        public GoogleServiceProvider()
        {
            Protocol = AuthProtocol.OAuth20;
            UserLocationStorageType = UserLocationStorageType.State;
            UserAuthorizationUrl = "https://accounts.google.com/o/oauth2/v2/auth";
            AccessTokenUrl = "https://oauth2.googleapis.com/token";
            ProfileUrl = "https://openidconnect.googleapis.com/v1/userinfo";
            OAuth2AccessTokenMethod = "POST";

            Scope = "email profile";
            State["token"] = "S0ftF1u3nt";
        }

        protected override UserData GetUserData(IDictionary<string, object> data)
        {
            if (data == null || data.Count == 0)
                return null;

            UserData userData = CreateUserData(data);
            if (data.ContainsKey("name"))
            {
                userData.Name = data["name"] as string;
            }

            if (data.ContainsKey("given_name"))
            {
                userData.FirstName = data["given_name"] as string;
            }

            if (data.ContainsKey("family_name"))
            {
                userData.LastName = data["family_name"] as string;
            }

            if (data.ContainsKey("email"))
            {
                userData.Email = data["email"] as string;
            }

            if (data.ContainsKey("gender"))
            {
                userData.Gender = data["gender"] as string;
            }
            return userData;
        }
    }
}
