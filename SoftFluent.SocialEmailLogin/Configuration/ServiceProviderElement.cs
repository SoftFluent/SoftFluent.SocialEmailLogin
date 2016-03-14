using System;
using System.Configuration;

namespace SoftFluent.SocialEmailLogin.Configuration
{
    public class ServiceProviderElement : ConfigurationElement
    {
        private AuthServiceProvider _authServiceProvider;

        [ConfigurationProperty("name", IsRequired = true, IsKey = true)]
        public string Name
        {
            get
            {
                return (string)base["name"];
            }
        }

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
        public string TypeName
        {
            get
            {
                return (string)base["typeName"];
            }
        }

        [ConfigurationProperty("consumerKey", IsRequired = false)]
        public string ConsumerKey
        {
            get
            {
                return (string)base["consumerKey"];
            }
        }

        [ConfigurationProperty("consumerSecret", IsRequired = false)]
        public string ConsumerSecret
        {
            get
            {
                return (string)base["consumerSecret"];
            }
        }

        [ConfigurationProperty("fakeEmailDomain", IsRequired = false)]
        public string FakeEmailDomain
        {
            get
            {
                return (string)base["fakeEmailDomain"];
            }
        }

        [ConfigurationProperty("requestTokenUrl", IsRequired = false)]
        public string RequestTokenUrl
        {
            get
            {
                return (string)base["requestTokenUrl"];
            }
        }

        [ConfigurationProperty("userAuthorizationUrl", IsRequired = false)]
        public string UserAuthorizationUrl
        {
            get
            {
                return (string)base["userAuthorizationUrl"];
            }
        }

        [ConfigurationProperty("discoveryUrl", IsRequired = false)]
        public string DiscoveryUrl
        {
            get
            {
                return (string)base["discoveryUrl"];
            }
        }

        [ConfigurationProperty("requestCallback", IsRequired = false)]
        public string RequestCallback
        {
            get
            {
                return (string)base["requestCallback"];
            }
        }

        [ConfigurationProperty("scope", IsRequired = false)]
        public string Scope
        {
            get
            {
                return (string)base["scope"];
            }
        }

        [ConfigurationProperty("protocol", IsRequired = false, DefaultValue = AuthProtocol.Undefined)]
        public AuthProtocol Protocol
        {
            get
            {
                return (AuthProtocol)base["protocol"];
            }
        }

        [ConfigurationProperty("successUrl")]
        public string SuccessUrl
        {
            get
            {
                return (string)base["successUrl"];
            }
        }

        [ConfigurationProperty("maintainUserLocation", DefaultValue = true)]
        public bool MaintainUserLocation
        {
            get
            {
                return (bool)base["maintainUserLocation"];
            }
        }

        [ConfigurationProperty("userLocationStorageType", DefaultValue = UserLocationStorageType.State)]
        public UserLocationStorageType UserLocationStorageType
        {
            get
            {
                return (UserLocationStorageType)base["userLocationStorageType"];
            }
        }

        [ConfigurationProperty("enabled", IsRequired = false, DefaultValue = true)]
        public bool Enabled
        {
            get
            {
                return (bool)base["enabled"];
            }
        }

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
