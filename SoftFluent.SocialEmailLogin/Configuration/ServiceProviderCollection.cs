using System;
using System.Collections.Generic;
using System.Configuration;

namespace SoftFluent.SocialEmailLogin.Configuration
{
    [ConfigurationCollection(typeof(ServiceProvider), AddItemName = "serviceProvider", CollectionType = ConfigurationElementCollectionType.BasicMap)]
    public class ServiceProviderCollection : ConfigurationElementCollection
    {
        protected override ConfigurationElement CreateNewElement()
        {
            return new ServiceProvider();
        }

        protected override object GetElementKey(ConfigurationElement element)
        {
            if (element == null)
                throw new ArgumentNullException("element");

            return ((ServiceProvider)element).Name;
        }

        public new ServiceProvider this[string name]
        {
            get
            {
                if (name == null)
                    return null;

                return (ServiceProvider)BaseGet(name);
            }
        }

        public static IEnumerable<ServiceProvider> SelectCurrent()
        {
            foreach (ServiceProvider provider in SocialEmailLoginSection.Current.Authentication.ServiceProviders)
            {
                if (provider.Enabled)
                    yield return provider;
            }
        }
    }
}
