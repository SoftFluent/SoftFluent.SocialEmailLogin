using System;
using System.Collections.Generic;
using System.Text;
using System.Web;
using System.Web.Script.Serialization;

namespace SoftFluent.SocialEmailLogin.Utilities
{
    internal static class Extensions
    {
        private const string _hexaChars = "0123456789ABCDEF";

        public static string ToHexa(byte[] bytes)
        {
            if (bytes == null)
                return null;

            return ToHexa(bytes, 0, bytes.Length);
        }

        public static string ToHexa(byte[] bytes, int offset, int count)
        {
            if (bytes == null)
                return string.Empty;

            if (offset < 0)
                throw new ArgumentException(null, nameof(offset));

            if (count < 0)
                throw new ArgumentException(null, nameof(count));

            if (offset >= bytes.Length)
                return string.Empty;

            count = Math.Min(count, bytes.Length - offset);
            var sb = new StringBuilder(count * 2);
            for (int i = offset; i < (offset + count); i++)
            {
                sb.Append(_hexaChars[bytes[i] / 16]);
                sb.Append(_hexaChars[bytes[i] % 16]);
            }
            return sb.ToString();
        }

        public static bool IsNullable(this Type type)
        {
            if (type == null)
                return false;

            return type.IsGenericType && type.GetGenericTypeDefinition() == typeof(Nullable<>);
        }

        public static string Nullify(this string text, bool trim)
        {
            if (text == null)
                return text;

            string strim = text.Trim();
            if (strim.Length == 0)
                return null;

            if (trim)
                return strim;

            return text;
        }

        public static TResult GetValue<TKey, TValue, TResult>(this IDictionary<TKey, TValue> dict, TKey name, TResult defaultValue)
        {
            if (dict == null)
                return defaultValue;

            if (dict.TryGetValue(name, out TValue v))
                return ConvertUtilities.ChangeType(v, defaultValue);

            return defaultValue;
        }

        public static IDictionary<string, string> ParseQueryString(string queryString)
        {
            var result = new Dictionary<string, string>();
            if (queryString == null)
                return result;

            if (queryString.StartsWith("?"))
            {
                queryString = queryString.Substring(1);
            }

            var parts = queryString.Split('&');
            foreach (var part in parts)
            {
                if (string.IsNullOrEmpty(part))
                    continue;

                int index = part.IndexOf('=');
                if (index <= 0)
                {
                    result[part] = null;
                }
                else
                {
                    result[part.Substring(0, index)] = HttpUtility.UrlDecode(part.Substring(index + 1));
                }
            }

            return result;
        }

        public static T GetQueryStringParameter<T>(string uri, string parameterName, T defaultValue)
        {
            var parameters = ParseQueryString(uri);
            if (parameters.TryGetValue(parameterName, out string value))
                return ConvertUtilities.ChangeType(value, defaultValue);

            return defaultValue;
        }

        public static string BuildQueryString(IDictionary<string, string> values)
        {
            if (values == null)
                throw new ArgumentNullException(nameof(values));

            bool first = true;
            var sb = new StringBuilder();
            foreach (var value in values)
            {
                if (value.Value == null)
                    continue;

                if (!first)
                {
                    sb.Append('&');
                }

                sb.Append(HttpUtility.UrlEncode(value.Key));
                sb.Append('=');
                sb.Append(HttpUtility.UrlEncode(value.Value));
                first = false;
            }

            return sb.ToString();
        }

        public static IDictionary<string, object> JsonDeserialize(string json)
        {
            if (json == null)
                return null;

            var serializer = new JavaScriptSerializer();
            object obj = serializer.Deserialize<object>(json);
            return obj as IDictionary<string, object>;
        }

        public static string JsonSerialize(object value)
        {
            var serializer = new JavaScriptSerializer();
            return serializer.Serialize(value);
        }
    }
}