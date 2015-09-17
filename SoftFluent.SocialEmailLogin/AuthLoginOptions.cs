using System;

namespace SoftFluent.SocialEmailLogin
{
    [Flags]
    public enum AuthLoginOptions
    {
        None = 0x0,
        Device = 0x1,
        RegisterApplication = 0x2,
    }
}
