using System;

namespace SoftFluent.SocialEmailLogin.Web.Security
{
    [Flags]
    public enum AuthLoginOptions
    {
        None = 0x0,
        Device = 0x1,
    }
}
