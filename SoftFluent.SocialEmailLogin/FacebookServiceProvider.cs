using System.Collections.Generic;

namespace SoftFluent.SocialEmailLogin
{
    public class FacebookServiceProvider : AuthServiceProvider
    {
        public FacebookServiceProvider()
        {
            Protocol = AuthProtocol.OAuth20;
            UserLocationStorageType = UserLocationStorageType.State;
            UserAuthorizationUrl = "https://www.facebook.com/dialog/oauth";
            AccessTokenUrl = "https://graph.facebook.com/oauth/access_token";
            ProfileUrl = "https://graph.facebook.com/v2.4/me?fields=id,name,email"; // https://developers.facebook.com/docs/graph-api/reference/user

            // http://stackoverflow.com/questions/5625532/facebook-c-sharp-sdk-get-users-email
            Scope = "email,public_profile";            
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

            if (data.ContainsKey("gender"))
            {
                userData.Gender = data["gender"] as string;
            }

            return userData;
        }
    }
}
