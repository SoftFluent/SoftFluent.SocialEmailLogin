using System;
using System.Collections.Generic;
using System.Web;

namespace SoftFluent.SocialEmailLogin
{
    public class HeadersEventArgs : EventArgs
    {
        public HeadersEventArgs(HttpContext context, IDictionary<string, string> headers)
        {
            Context = context ?? throw new ArgumentNullException(nameof(context));
            Headers = headers ?? throw new ArgumentNullException(nameof(headers));
        }

        public HttpContext Context { get; private set; }
        public IDictionary<string, string> Headers { get; private set; }
    }
}
