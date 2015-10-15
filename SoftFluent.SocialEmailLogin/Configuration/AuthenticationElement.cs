using System;
using System.Configuration;

namespace SoftFluent.SocialEmailLogin.Configuration
{
    public class AuthenticationElement : ConfigurationElement
    {
        [ConfigurationProperty("serviceProviders", IsDefaultCollection = false, IsRequired = false)]
        public virtual ServiceProviderElementCollection ServiceProviders
        {
            get
            {
                return (ServiceProviderElementCollection)this["serviceProviders"];
            }
        }

        [ConfigurationProperty("providerNameComparison", DefaultValue = StringComparison.OrdinalIgnoreCase)]
        public virtual StringComparison ProviderNameComparison
        {
            get
            {
                return (StringComparison)this["providerNameComparison"];
            }
        }

        [ConfigurationProperty("maximumRetryCount", DefaultValue = 10)]
        public virtual int MaximumRetryCount
        {
            get
            {
                return (int)this["maximumRetryCount"];
            }
        }
        
        [ConfigurationProperty("retryInterval", DefaultValue = 50)]
        public virtual int RetryInterval
        {
            get
            {
                return (int)this["retryInterval"];
            }
        }

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
