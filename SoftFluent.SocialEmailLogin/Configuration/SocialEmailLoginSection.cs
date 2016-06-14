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
                        throw new AuthException("OA0008: Missing '" + SectionName + "' section in " + AppDomain.CurrentDomain.SetupInformation.ConfigurationFile);
                }
                return _current;
            }
            set
            {
                _current = value;
            }
        }

        public static SocialEmailLoginSection Get(XmlReader reader)
        {
            if (reader == null)
                throw new ArgumentNullException(nameof(reader));

            var section = new SocialEmailLoginSection();
            section.DeserializeSection(reader);
            return section;
        }

        [ConfigurationProperty("authentication", Options = ConfigurationPropertyOptions.IsRequired)]
        public AuthenticationElement Authentication => (AuthenticationElement)this["authentication"];
    }
}
