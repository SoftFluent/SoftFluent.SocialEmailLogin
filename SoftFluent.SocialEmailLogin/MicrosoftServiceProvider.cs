using System.Collections.Generic;

namespace SoftFluent.SocialEmailLogin
{
    public class MicrosoftServiceProvider : AuthServiceProvider
    {
        private static readonly string[] OrderedEmailKeys = new string[] { "account", "preferred", "personal", "business" };

        public MicrosoftServiceProvider()
        {
            Protocol = AuthProtocol.OAuth20;
            UserLocationStorageType = UserLocationStorageType.State;
            UserAuthorizationUrl = "https://login.live.com/oauth20_authorize.srf";
            AccessTokenUrl = "https://login.live.com/oauth20_token.srf";
            ProfileUrl = "https://apis.live.net/v5.0/me";

            //  http://stackoverflow.com/questions/9766771/using-live-connect-api-in-asp-net-to-retrieve-a-users-email-address
            Scope = "wl.emails";
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

            if (data.ContainsKey("gender"))
            {
                userData.Gender = data["gender"] as string;
            }

            if (data.ContainsKey("emails"))
            {
                var emails = data["emails"] as Dictionary<string, object>;
                if (emails != null)
                {
                    foreach (string emailKey in OrderedEmailKeys)
                    {
                        if (emails.ContainsKey(emailKey))
                        {
                            userData.Email = emails[emailKey] as string;
                            if (!string.IsNullOrEmpty(userData.Email))
                                break;
                        }
                    }
                }
            }
            return userData;
        }
    }
}
