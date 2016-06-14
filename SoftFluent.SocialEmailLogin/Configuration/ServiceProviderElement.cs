using System;
using System.Configuration;

namespace SoftFluent.SocialEmailLogin.Configuration
{
    public class ServiceProviderElement : ConfigurationElement
    {
        private AuthServiceProvider _authServiceProvider;

        [ConfigurationProperty("name", IsRequired = true, IsKey = true)]
        public string Name => (string)base["name"];

        [ConfigurationProperty("displayName", IsRequired = false)]
        public string DisplayName
        {
            get
            {
                string name = (string)base["displayName"];
                if (string.IsNullOrEmpty(name))
                    return Name;

                return name;
            }
        }

        [ConfigurationProperty("typeName", IsRequired = false)]
        public string TypeName => (string)base["typeName"];

        [ConfigurationProperty("consumerKey", IsRequired = false)]
        public string ConsumerKey => (string)base["consumerKey"];

        [ConfigurationProperty("consumerSecret", IsRequired = false)]
        public string ConsumerSecret => (string)base["consumerSecret"];

        [ConfigurationProperty("fakeEmailDomain", IsRequired = false)]
        public string FakeEmailDomain => (string)base["fakeEmailDomain"];

        [ConfigurationProperty("requestTokenUrl", IsRequired = false)]
        public string RequestTokenUrl => (string)base["requestTokenUrl"];

        [ConfigurationProperty("userAuthorizationUrl", IsRequired = false)]
        public string UserAuthorizationUrl => (string)base["userAuthorizationUrl"];

        [ConfigurationProperty("discoveryUrl", IsRequired = false)]
        public string DiscoveryUrl => (string)base["discoveryUrl"];

        [ConfigurationProperty("requestCallback", IsRequired = false)]
        public string RequestCallback => (string)base["requestCallback"];

        [ConfigurationProperty("scope", IsRequired = false)]
        public string Scope => (string)base["scope"];

        [ConfigurationProperty("protocol", IsRequired = false, DefaultValue = AuthProtocol.Undefined)]
        public AuthProtocol Protocol => (AuthProtocol)base["protocol"];

        [ConfigurationProperty("successUrl")]
        public string SuccessUrl => (string)base["successUrl"];

        [ConfigurationProperty("maintainUserLocation", DefaultValue = true)]
        public bool MaintainUserLocation => (bool)base["maintainUserLocation"];

        [ConfigurationProperty("userLocationStorageType", DefaultValue = UserLocationStorageType.State)]
        public UserLocationStorageType UserLocationStorageType => (UserLocationStorageType)base["userLocationStorageType"];

        [ConfigurationProperty("enabled", IsRequired = false, DefaultValue = true)]
        public bool Enabled => (bool)base["enabled"];

        public AuthServiceProvider AuthServiceProvider
        {
            get
            {
                if (_authServiceProvider == null)
                {
                    string typeName = TypeName;
                    var type = Type.GetType(typeName, false);
                    if (type == null)
                    {
                        if (string.IsNullOrEmpty(typeName))
                        {
                            //SoftFluent.SocialEmailLogin.FacebookServiceProvider
                            typeName = typeof(AuthServiceProvider).Namespace + "." + Name + "ServiceProvider, " + typeof(AuthServiceProvider).Assembly;
                        }

                        type = Type.GetType(typeName, true);
                    }

                    _authServiceProvider = Activator.CreateInstance(type) as AuthServiceProvider;
                    if (_authServiceProvider == null)
                        throw new Exception();

                    _authServiceProvider.Name = Name;
                    _authServiceProvider.UserLocationStorageType = UserLocationStorageType;

                    if (Protocol != AuthProtocol.Undefined)
                    {
                        _authServiceProvider.Protocol = Protocol;
                    }

                    _authServiceProvider.ConsumerKey = ConsumerKey;
                    _authServiceProvider.ConsumerSecret = ConsumerSecret;

                    if (!string.IsNullOrEmpty(FakeEmailDomain))
                    {
                        _authServiceProvider.FakeEmailDomain = FakeEmailDomain;
                    }

                    if (!string.IsNullOrEmpty(RequestTokenUrl))
                    {
                        _authServiceProvider.RequestTokenUrl = RequestTokenUrl;
                    }

                    if (!string.IsNullOrEmpty(UserAuthorizationUrl))
                    {
                        _authServiceProvider.UserAuthorizationUrl = UserAuthorizationUrl;
                    }

                    if (!string.IsNullOrEmpty(RequestCallback))
                    {
                        _authServiceProvider.RequestCallback = RequestCallback;
                    }

                    if (!string.IsNullOrEmpty(Scope))
                    {
                        _authServiceProvider.Scope = Scope;
                    }

                    if (!string.IsNullOrEmpty(DiscoveryUrl))
                    {
                        _authServiceProvider.DiscoveryUrl = DiscoveryUrl;
                    }

                    if (!string.IsNullOrEmpty(SuccessUrl))
                    {
                        _authServiceProvider.SuccessUrl = SuccessUrl;
                    }
                }
                return _authServiceProvider;
            }
        }
    }
}
