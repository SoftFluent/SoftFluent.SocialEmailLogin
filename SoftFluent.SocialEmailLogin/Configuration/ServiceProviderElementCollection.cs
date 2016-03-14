using System;
using System.Collections.Generic;
using System.Configuration;

namespace SoftFluent.SocialEmailLogin.Configuration
{
    [ConfigurationCollection(typeof(ServiceProviderElement), AddItemName = "serviceProvider", CollectionType = ConfigurationElementCollectionType.BasicMap)]
    public class ServiceProviderElementCollection : ConfigurationElementCollection
    {
        protected override ConfigurationElement CreateNewElement()
        {
            return new ServiceProviderElement();
        }

        protected override object GetElementKey(ConfigurationElement element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            return ((ServiceProviderElement)element).Name;
        }

        public new ServiceProviderElement this[string name]
        {
            get
            {
                if (name == null)
                    return null;

                return (ServiceProviderElement)BaseGet(name);
            }
        }

        public static IEnumerable<ServiceProviderElement> SelectCurrent()
        {
            foreach (ServiceProviderElement provider in SocialEmailLoginSection.Current.Authentication.ServiceProviders)
            {
                if (provider.Enabled)
                    yield return provider;
            }
        }
    }
}
