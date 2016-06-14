using System;
using System.Collections.Generic;
using System.Web;

namespace SoftFluent.SocialEmailLogin
{
    public class HeadersEventArgs : EventArgs
    {
        public HeadersEventArgs(HttpContext context, IDictionary<string, string> headers)
        {
            if (context == null)
                throw new ArgumentNullException("context");

            if (headers == null)
                throw new ArgumentNullException("headers");

            Context = context;
            Headers = headers;
        }

        public HttpContext Context { get; private set; }
        public IDictionary<string, string> Headers { get; private set; }
    }
}
