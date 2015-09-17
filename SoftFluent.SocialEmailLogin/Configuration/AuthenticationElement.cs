using System.Configuration;

namespace SoftFluent.SocialEmailLogin.Configuration
{
    public class AuthenticationElement : ConfigurationElement
    {
        [ConfigurationProperty("serviceProviders", IsDefaultCollection = false, IsRequired = false)]
        public ServiceProviderElementCollection ServiceProviders
        {
            get
            {
                return (ServiceProviderElementCollection)this["serviceProviders"];
            }
        }

        public AuthServiceProvider GetServiceProvider(string name)
        {
            if (name == null)
                return null;

            foreach (ServiceProviderElement provider in ServiceProviders)
            {
                if ((provider.Name == name) && (provider.Enabled))
                    return provider.AuthServiceProvider;
            }
            return null;
        }
    }
}
