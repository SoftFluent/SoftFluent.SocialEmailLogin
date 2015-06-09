using System;
using System.Configuration;
using System.Xml;

namespace SoftFluent.SocialEmailLogin.Configuration
{
    public class SocialEmailLoginSection : ConfigurationSection
    {
        public static readonly string SectionName = "SoftFluent.SocialEmailLoginSection";
        private static SocialEmailLoginSection _current;

        private SocialEmailLoginSection()
        {
        }

        public static SocialEmailLoginSection Current
        {
            get
            {
                if (_current == null)
                {
                    _current = ConfigurationManager.GetSection(SectionName) as SocialEmailLoginSection;
                    if (_current == null)
                        throw new Exception("Missing '" + SectionName + "' section in " + AppDomain.CurrentDomain.SetupInformation.ConfigurationFile);
                }
                return _current;
            }
        }

        public static SocialEmailLoginSection Get(XmlReader reader)
        {
            if (reader == null)
                return Current;

            SocialEmailLoginSection section = new SocialEmailLoginSection();
            section.DeserializeSection(reader);
            return section;
        }

        [ConfigurationProperty("authentication", Options = ConfigurationPropertyOptions.IsRequired)]
        public AuthenticationElement Authentication
        {
            get
            {
                return (AuthenticationElement)this["authentication"];
            }
        }

        [ConfigurationProperty("updateUserLastActivity", IsRequired = false, DefaultValue = true)]
        public bool UpdateUserLastActivity
        {
            get
            {
                return (bool)base["updateUserLastActivity"];
            }
        }
    }
}
