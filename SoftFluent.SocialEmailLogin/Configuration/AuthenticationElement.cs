using System;
using System.Configuration;

namespace SoftFluent.SocialEmailLogin.Configuration
{
    public class AuthenticationElement : ConfigurationElement
    {
        [ConfigurationProperty("serviceProviders", IsDefaultCollection = false, IsRequired = false)]
        public virtual ServiceProviderElementCollection ServiceProviders => (ServiceProviderElementCollection)this["serviceProviders"];

        [ConfigurationProperty("providerNameComparison", DefaultValue = StringComparison.OrdinalIgnoreCase)]
        public virtual StringComparison ProviderNameComparison => (StringComparison)this["providerNameComparison"];

        [ConfigurationProperty("maximumRetryCount", DefaultValue = 10)]
        public virtual int MaximumRetryCount => (int)this["maximumRetryCount"];

        [ConfigurationProperty("retryInterval", DefaultValue = 50)]
        public virtual int RetryInterval => (int)this["retryInterval"];

        public virtual AuthServiceProvider GetServiceProvider(string name)
        {
            return GetServiceProvider(name, ProviderNameComparison);
        }

        public virtual AuthServiceProvider GetServiceProvider(string name, StringComparison stringComparison)
        {
            if (name == null)
                return null;

            foreach (ServiceProviderElement provider in ServiceProviders)
            {
                if (provider.Enabled && string.Equals(provider.Name, name, ProviderNameComparison))
                    return provider.AuthServiceProvider;
            }
            return null;
        }
    }
}
