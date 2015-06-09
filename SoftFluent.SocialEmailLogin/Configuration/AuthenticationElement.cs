using System.Configuration;
using SoftFluent.SocialEmailLogin.Web.Security;

namespace SoftFluent.SocialEmailLogin.Configuration
{
    public class AuthenticationElement : ConfigurationElement
    {
        [ConfigurationProperty("serviceProviders", IsDefaultCollection = false, IsRequired = false)]
        public ServiceProviderCollection ServiceProviders
        {
            get
            {
                return (ServiceProviderCollection)this["serviceProviders"];
            }
        }

        public AuthServiceProvider GetServiceProvider(string name)
        {
            if (name == null)
                return null;

            foreach (ServiceProvider provider in ServiceProviders)
            {
                if ((provider.Name == name) && (provider.Enabled))
                    return provider.AuthServiceProvider;
            }
            return null;
        }
    }
}
