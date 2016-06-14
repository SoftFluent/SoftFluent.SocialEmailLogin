using System;
using System.Collections.Generic;

namespace SoftFluent.SocialEmailLogin
{
    public class UserData
    {
        private string _fullName;

        public UserData(IDictionary<string, object> data)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));

            Data = data;
        }
        
        public IDictionary<string, object> Data { get; }

        public string Email { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Gender { get; set; }

        public string Name
        {
            get
            {
                if (_fullName == null)
                {
                    if (FirstName != null && LastName != null)
                        return FirstName + " " + LastName;

                    if (FirstName != null)
                        return FirstName;

                    return LastName;
                }

                return _fullName;
            }
            set
            {
                _fullName = value;
            }
        }
    }
}
