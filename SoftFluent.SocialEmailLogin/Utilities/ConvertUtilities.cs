﻿using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Reflection;

namespace SoftFluent.SocialEmailLogin.Utilities
{
    internal class ConvertUtilities
    {
        private static byte GetHexaByte(char c)
        {
            if (c >= '0' && c <= '9')
                return (byte)(c - '0');

            if (c >= 'A' && c <= 'F')
                return (byte)(c - 'A' + 10);

            if (c >= 'a' && c <= 'f')
                return (byte)(c - 'a' + 10);

            return 0xFF;
        }

        private static bool TryConvert(string text, out byte[] value)
        {
            if (text == null)
            {
                value = null;
                return true;
            }

            var list = new List<byte>();
            bool lo = false;
            byte prev = 0;
            int offset;

            // handle 0x or 0X notation
            if (text.Length >= 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X'))
            {
                offset = 2;
            }
            else
            {
                offset = 0;
            }
            for (int i = 0; i < text.Length - offset; i++)
            {
                byte b = GetHexaByte(text[i + offset]);
                if (b == 0xFF)
                {
                    value = null;
                    return false;
                }

                if (lo)
                {
                    list.Add((byte)(prev * 16 + b));
                }
                else
                {
                    prev = b;
                }
                lo = !lo;
            }

            value = list.ToArray();
            return true;
        }

        private static bool NormalizeHexString(ref string s)
        {
            if (s == null)
                return false;

            if (s.Length > 0)
            {
                if (s[0] == 'x' || s[0] == 'X')
                {
                    s = s.Substring(1);
                    return true;
                }

                if (s.Length > 1)
                {
                    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
                    {
                        s = s.Substring(2);
                        return true;
                    }
                }
            }
            return false;
        }

        private static void GetBytes(decimal d, byte[] buffer)
        {
            var ints = decimal.GetBits(d);
            buffer[0] = (byte)ints[0];
            buffer[1] = (byte)(ints[0] >> 8);
            buffer[2] = (byte)(ints[0] >> 0x10);
            buffer[3] = (byte)(ints[0] >> 0x18);
            buffer[4] = (byte)ints[1];
            buffer[5] = (byte)(ints[1] >> 8);
            buffer[6] = (byte)(ints[1] >> 0x10);
            buffer[7] = (byte)(ints[1] >> 0x18);
            buffer[8] = (byte)ints[2];
            buffer[9] = (byte)(ints[2] >> 8);
            buffer[10] = (byte)(ints[2] >> 0x10);
            buffer[11] = (byte)(ints[2] >> 0x18);
            buffer[12] = (byte)ints[3];
            buffer[13] = (byte)(ints[3] >> 8);
            buffer[14] = (byte)(ints[3] >> 0x10);
            buffer[15] = (byte)(ints[3] >> 0x18);
        }

        private static bool TryConvert(object input, IFormatProvider provider, out DateTimeOffset value)
        {
            if (DateTimeOffset.TryParse(Convert.ToString(input, provider), provider, DateTimeStyles.None, out value))
                return true;

            if (TryConvert(input, provider, out DateTime dt))
            {
                value = new DateTimeOffset(dt);
                return true;
            }
            value = DateTimeOffset.MinValue;
            return false;
        }

        private static bool TryConvert(object input, IFormatProvider provider, out TimeSpan value)
        {
            if (TimeSpan.TryParse(Convert.ToString(input, provider), provider, out value))
                return true;

            if (TryConvert(input, provider, out long l))
            {
                value = new TimeSpan(l);
                return true;
            }
            value = TimeSpan.Zero;
            return false;
        }

        private static bool TryConvert(object input, IFormatProvider provider, out IntPtr value)
        {
            value = IntPtr.Zero;
            if (IntPtr.Size == 4)
            {
                if (TryConvert(input, provider, out int i))
                {
                    value = new IntPtr(i);
                    return true;
                }
                return false;
            }

            if (TryConvert(input, provider, out long l))
            {
                value = new IntPtr(l);
                return true;
            }
            return false;
        }

        private static bool TryConvert(object input, IFormatProvider provider, out Guid value)
        {
            if (input is byte[] inputBytes)
            {
                if (inputBytes.Length != 16)
                {
                    value = Guid.Empty;
                    return false;
                }

                value = new Guid(inputBytes);
                return true;
            }

            return Guid.TryParse(Convert.ToString(input, provider), out value);
        }

        private static bool TryConvert(object input, IFormatProvider provider, out ulong value)
        {
            if (input is IConvertible ic)
            {
                try
                {
                    value = ic.ToUInt64(provider);
                    return true;
                }
                catch
                {
                }
            }

            var styles = NumberStyles.Integer;
            string s = Convert.ToString(input, provider);
            if (NormalizeHexString(ref s))
            {
                styles |= NumberStyles.AllowHexSpecifier;
            }
            return ulong.TryParse(s, styles, provider, out value);
        }

        private static bool TryConvert(object input, IFormatProvider provider, out ushort value)
        {
            if (input is IConvertible ic)
            {
                try
                {
                    value = ic.ToUInt16(provider);
                    return true;
                }
                catch
                {
                }
            }

            var styles = NumberStyles.Integer;
            string s = Convert.ToString(input, provider);
            if (NormalizeHexString(ref s))
            {
                styles |= NumberStyles.AllowHexSpecifier;
            }
            return ushort.TryParse(s, styles, provider, out value);
        }

        private static bool TryConvert(object input, IFormatProvider provider, out decimal value)
        {
            if (input is IConvertible ic)
            {
                try
                {
                    value = ic.ToDecimal(provider);
                    return true;
                }
                catch
                {
                }
            }

            var styles = NumberStyles.Integer;
            string s = Convert.ToString(input, provider);
            if (NormalizeHexString(ref s))
            {
                styles |= NumberStyles.AllowHexSpecifier;
            }
            return decimal.TryParse(s, styles, provider, out value);
        }

        private static bool TryConvert(object input, IFormatProvider provider, out float value)
        {
            if (input is IConvertible ic)
            {
                try
                {
                    value = ic.ToSingle(provider);
                    return true;
                }
                catch
                {
                }
            }

            var styles = NumberStyles.Integer;
            string s = Convert.ToString(input, provider);
            if (NormalizeHexString(ref s))
            {
                styles |= NumberStyles.AllowHexSpecifier;
            }
            return float.TryParse(s, styles, provider, out value);
        }

        private static bool TryConvert(object input, IFormatProvider provider, out double value)
        {
            value = 0;
            if (input is IConvertible ic)
            {
                try
                {
                    value = ic.ToDouble(provider);
                    return true;
                }
                catch
                {
                }
            }

            var styles = NumberStyles.Integer;
            string s = Convert.ToString(input, provider);
            if (NormalizeHexString(ref s))
            {
                styles |= NumberStyles.AllowHexSpecifier;
            }
            return double.TryParse(s, styles, provider, out value);
        }

        private static bool TryConvert(object input, IFormatProvider provider, out char value)
        {
            if (input is IConvertible ic)
            {
                try
                {
                    value = ic.ToChar(provider);
                    return true;
                }
                catch
                {
                }
            }

            string s = Convert.ToString(input, provider);
            return char.TryParse(s, out value);
        }

        private static bool TryConvert(object input, IFormatProvider provider, out DateTime value)
        {
            if (input is IConvertible ic)
            {
                try
                {
                    value = ic.ToDateTime(provider);
                    return true;
                }
                catch
                {
                }
            }

            string s = Convert.ToString(input, provider);
            return DateTime.TryParse(s, provider, DateTimeStyles.None, out value);
        }

        private static bool TryConvert(object input, IFormatProvider provider, out uint value)
        {
            if (input is IConvertible ic)
            {
                try
                {
                    value = ic.ToUInt32(provider);
                    return true;
                }
                catch
                {
                }
            }

            var styles = NumberStyles.Integer;
            string s = Convert.ToString(input, provider);
            if (NormalizeHexString(ref s))
            {
                styles |= NumberStyles.AllowHexSpecifier;
            }
            return uint.TryParse(s, styles, provider, out value);
        }

        private static bool TryConvert(object input, IFormatProvider provider, out byte value)
        {
            if (input is IConvertible ic)
            {
                try
                {
                    value = ic.ToByte(provider);
                    return true;
                }
                catch
                {
                }
            }

            var styles = NumberStyles.Integer;
            string s = Convert.ToString(input, provider);
            if (NormalizeHexString(ref s))
            {
                styles |= NumberStyles.AllowHexSpecifier;
            }
            return byte.TryParse(s, styles, provider, out value);
        }

        private static bool TryConvert(object input, IFormatProvider provider, out sbyte value)
        {
            if (input is IConvertible ic)
            {
                try
                {
                    value = ic.ToSByte(provider);
                    return true;
                }
                catch
                {
                }
            }

            var styles = NumberStyles.Integer;
            string s = Convert.ToString(input, provider);
            if (NormalizeHexString(ref s))
            {
                styles |= NumberStyles.AllowHexSpecifier;
            }
            return sbyte.TryParse(s, styles, provider, out value);
        }

        private static bool TryConvert(object input, IFormatProvider provider, out short value)
        {
            value = 0;
            if (input is byte[] inputBytes)
            {
                if (inputBytes.Length == 2)
                {
                    value = BitConverter.ToInt16(inputBytes, 0);
                    return true;
                }
                return false;
            }

            if (input is IConvertible ic)
            {
                try
                {
                    value = ic.ToInt16(provider);
                    return true;
                }
                catch
                {
                }
            }

            var styles = NumberStyles.Integer;
            string s = Convert.ToString(input, provider);
            if (NormalizeHexString(ref s))
            {
                styles |= NumberStyles.AllowHexSpecifier;
            }
            return short.TryParse(s, styles, provider, out value);
        }

        private static bool TryConvert(object input, IFormatProvider provider, out int value)
        {
            value = 0;
            if (input is byte[] inputBytes)
            {
                if (inputBytes.Length == 4)
                {
                    value = BitConverter.ToInt32(inputBytes, 0);
                    return true;
                }
                return false;
            }

            if (input is IntPtr)
            {
                value = ((IntPtr)input).ToInt32();
                return true;
            }

            if (input is IConvertible ic)
            {
                try
                {
                    value = ic.ToInt32(provider);
                    return true;
                }
                catch
                {
                }
            }

            var styles = NumberStyles.Integer;
            string s = Convert.ToString(input, provider);
            if (NormalizeHexString(ref s))
            {
                styles |= NumberStyles.AllowHexSpecifier;
            }
            return int.TryParse(s, styles, provider, out value);
        }

        private static bool TryConvert(object input, IFormatProvider provider, out long value)
        {
            value = 0;
            if (input is byte[] inputBytes)
            {
                if (inputBytes.Length == 8)
                {
                    value = BitConverter.ToInt64(inputBytes, 0);
                    return true;
                }
                return false;
            }

            if (input is IntPtr)
            {
                value = ((IntPtr)input).ToInt64();
                return true;
            }

            if (input is IConvertible ic)
            {
                try
                {
                    value = ic.ToInt64(provider);
                    return true;
                }
                catch
                {
                }
            }

            var styles = NumberStyles.Integer;
            string s = Convert.ToString(input, provider);
            if (NormalizeHexString(ref s))
            {
                styles |= NumberStyles.AllowHexSpecifier;
            }
            return long.TryParse(s, styles, provider, out value);
        }

        private static bool TryConvert(object input, IFormatProvider provider, out bool value)
        {
            value = false;
            if (input is byte[] inputBytes)
            {
                if (inputBytes.Length == 1)
                {
                    value = BitConverter.ToBoolean(inputBytes, 0);
                    return true;
                }
                return false;
            }

            if (TryConvert(input, typeof(long), provider, out object booll))
            {
                value = ((long)booll) != 0;
                return true;
            }

            string bools = Convert.ToString(input, provider);
            if (bools == null)
                return false; // arguable...

            bools = bools.Trim().ToLowerInvariant();
            if (bools == "y" || bools == "yes" || bools == "t" || bools.StartsWith("true"))
            {
                value = true;
                return true;
            }

            if (bools == "n" || bools == "no" || bools == "f" || bools.StartsWith("false"))
                return true;

            return false;
        }

        private static readonly MethodInfo _enumTryParse = typeof(Enum).GetMethods(BindingFlags.Public | BindingFlags.Static).First(m => m.Name == "TryParse" && m.GetParameters().Length == 3);

        private static bool EnumTryParse(Type type, string input, out object value)
        {
            MethodInfo mi = _enumTryParse.MakeGenericMethod(type);
            object[] args = { input, true, Enum.ToObject(type, 0) };
            bool b = (bool)mi.Invoke(null, args);
            value = args[2];
            return b;
        }

        public virtual bool TryChangeType(object input, Type conversionType, IFormatProvider provider, out object value)
        {
            return TryConvert(input, conversionType, provider, out value);
        }

        public static bool TryConvert(object input, Type conversionType, IFormatProvider provider, out object value)
        {
            if (conversionType == null)
                throw new ArgumentNullException(nameof(conversionType));

            if (conversionType == typeof(object))
            {
                value = input;
                return true;
            }

            if (input == null)
            {
                if (conversionType.IsNullable())
                {
                    value = null;
                    return true;
                }

                if (conversionType.IsValueType)
                {
                    value = Activator.CreateInstance(conversionType);
                    return false;
                }

                value = null;
                return true;
            }

            Type inputType = input.GetType();
            TypeCode inputCode = Type.GetTypeCode(inputType);
            TypeCode conversionCode = Type.GetTypeCode(conversionType);
            if (conversionType.IsAssignableFrom(inputType))
            {
                value = input;
                return true;
            }

            if (conversionType.IsNullable())
            {
                // en empty string is successfully converted into a nullable
                string inps = input as string;
                if (string.IsNullOrWhiteSpace(inps))
                {
                    value = null;
                    return true;
                }

                Type vtType = conversionType.GetGenericArguments()[0];
                if (TryConvert(input, vtType, provider, out object vtValue))
                {
                    Type nt = typeof(Nullable<>).MakeGenericType(vtType);
                    value = Activator.CreateInstance(nt, vtValue);
                    return true;
                }
                value = null;
                return false;
            }

            if (Convert.IsDBNull(input))
            {
                if (conversionType.IsValueType)
                {
                    value = Activator.CreateInstance(conversionType);
                    return false;
                }

                value = null;
                return true;
            }

            // enum must be before integers
            if (conversionType.IsEnum)
            {
                if (EnumTryParse(conversionType, Convert.ToString(input, provider), out value))
                    return true;
            }

            switch (conversionCode)
            {
                case TypeCode.Boolean:
                    bool boolValue;
                    if (TryConvert(input, provider, out boolValue))
                    {
                        value = boolValue;
                        return true;
                    }
                    break;

                case TypeCode.Byte:
                    byte byteValue;
                    if (TryConvert(input, provider, out byteValue))
                    {
                        value = byteValue;
                        return true;
                    }
                    break;

                case TypeCode.Char:
                    char charValue;
                    if (TryConvert(input, provider, out charValue))
                    {
                        value = charValue;
                        return true;
                    }
                    break;

                case TypeCode.DateTime:
                    DateTime dtValue;
                    if (TryConvert(input, provider, out dtValue))
                    {
                        value = dtValue;
                        return true;
                    }
                    break;

                case TypeCode.DBNull:
                    value = null;
                    return false;

                case TypeCode.Decimal:
                    decimal decValue;
                    if (TryConvert(input, provider, out decValue))
                    {
                        value = decValue;
                        return true;
                    }
                    break;

                case TypeCode.Double:
                    double dblValue;
                    if (TryConvert(input, provider, out dblValue))
                    {
                        value = dblValue;
                        return true;
                    }
                    break;

                case TypeCode.Int16:
                    short i16Value;
                    if (TryConvert(input, provider, out i16Value))
                    {
                        value = i16Value;
                        return true;
                    }
                    break;

                case TypeCode.Int32:
                    int i32Value;
                    if (TryConvert(input, provider, out i32Value))
                    {
                        value = i32Value;
                        return true;
                    }
                    break;

                case TypeCode.Int64:
                    long i64Value;
                    if (TryConvert(input, provider, out i64Value))
                    {
                        value = i64Value;
                        return true;
                    }
                    break;

                case TypeCode.SByte:
                    sbyte sbyteValue;
                    if (TryConvert(input, provider, out sbyteValue))
                    {
                        value = sbyteValue;
                        return true;
                    }
                    break;

                case TypeCode.Single:
                    float fltValue;
                    if (TryConvert(input, provider, out fltValue))
                    {
                        value = fltValue;
                        return true;
                    }
                    break;

                case TypeCode.String:
                    byte[] inputBytes = input as byte[];
                    if (inputBytes != null)
                    {
                        value = Extensions.ToHexa(inputBytes);
                    }
                    else
                    {
                        var tc = TypeDescriptor.GetConverter(inputType);
                        if (tc != null && tc.CanConvertTo(typeof(string)))
                        {
                            value = (string)tc.ConvertTo(input, typeof(string));
                        }
                        else
                        {
                            value = Convert.ToString(input, provider);
                        }
                    }
                    return true;

                case TypeCode.UInt16:
                    ushort u16Value;
                    if (TryConvert(input, provider, out u16Value))
                    {
                        value = u16Value;
                        return true;
                    }
                    break;

                case TypeCode.UInt32:
                    uint u32Value;
                    if (TryConvert(input, provider, out u32Value))
                    {
                        value = u32Value;
                        return true;
                    }
                    break;

                case TypeCode.UInt64:
                    ulong u64Value;
                    if (TryConvert(input, provider, out u64Value))
                    {
                        value = u64Value;
                        return true;
                    }
                    break;

                case TypeCode.Object:
                    if (conversionType == typeof(Guid))
                    {
                        if (TryConvert(input, provider, out Guid gValue))
                        {
                            value = gValue;
                            return true;
                        }
                    }

                    if (conversionType == typeof(IntPtr))
                    {
                        if (TryConvert(input, provider, out IntPtr ptr))
                        {
                            value = ptr;
                            return true;
                        }
                    }

                    if (conversionType == typeof(Version))
                    {
                        if (Version.TryParse(Convert.ToString(input, provider), out Version version))
                        {
                            value = version;
                            return true;
                        }
                    }

                    if (conversionType == typeof(IPAddress))
                    {
                        if (IPAddress.TryParse(Convert.ToString(input, provider), out IPAddress address))
                        {
                            value = address;
                            return true;
                        }
                    }

                    if (conversionType == typeof(DateTimeOffset))
                    {
                        if (TryConvert(input, provider, out DateTimeOffset dto))
                        {
                            value = dto;
                            return true;
                        }
                    }

                    if (conversionType == typeof(TimeSpan))
                    {
                        if (TryConvert(input, provider, out TimeSpan ts))
                        {
                            value = ts;
                            return true;
                        }
                    }

                    if (conversionType == typeof(byte[]))
                    {
                        switch (inputCode)
                        {
                            case TypeCode.Boolean:
                                value = BitConverter.GetBytes((bool)input);
                                return true;

                            case TypeCode.Char:
                                value = BitConverter.GetBytes((char)input);
                                return true;

                            case TypeCode.Double:
                                value = BitConverter.GetBytes((double)input);
                                return true;

                            case TypeCode.Int16:
                                value = BitConverter.GetBytes((short)input);
                                return true;

                            case TypeCode.Int32:
                                value = BitConverter.GetBytes((int)input);
                                return true;

                            case TypeCode.Int64:
                                value = BitConverter.GetBytes((long)input);
                                return true;

                            case TypeCode.Single:
                                value = BitConverter.GetBytes((float)input);
                                return true;

                            case TypeCode.UInt16:
                                value = BitConverter.GetBytes((ushort)input);
                                return true;

                            case TypeCode.UInt32:
                                value = BitConverter.GetBytes((uint)input);
                                return true;

                            case TypeCode.UInt64:
                                value = BitConverter.GetBytes((ulong)input);
                                return true;

                            case TypeCode.Byte:
                                value = new[] { (byte)input };
                                return true;

                            case TypeCode.DateTime:
                                value = BitConverter.GetBytes(((DateTime)input).ToOADate());
                                return true;

                            case TypeCode.Decimal:
                                var decBytes = new byte[16];
                                GetBytes((decimal)input, decBytes);
                                value = decBytes;
                                return true;

                            case TypeCode.SByte:
                                value = new[] { unchecked((byte)input) };
                                return true;

                            case TypeCode.String:
                                try
                                {
                                    value = Convert.FromBase64String((string)input);
                                    return true;
                                }
                                catch
                                {
                                    if (TryConvert((string)input, out byte[] ib))
                                    {
                                        value = ib;
                                        return true;
                                    }
                                }
                                value = null;
                                return false;

                            default:
                                if (input is Guid)
                                {
                                    value = ((Guid)input).ToByteArray();
                                    return true;
                                }

                                if (input is DateTimeOffset)
                                    return TryConvert(((DateTimeOffset)input).DateTime, conversionType, provider, out value);

                                if (input is TimeSpan)
                                {
                                    value = BitConverter.GetBytes(((TimeSpan)input).Ticks);
                                    return true;
                                }
                                break;
                        }
                    }
                    break;
            }

            TypeConverter ctConverter = null;
            try
            {
                ctConverter = TypeDescriptor.GetConverter(conversionType);
                if (ctConverter != null && ctConverter.CanConvertFrom(inputType))
                {
                    value = ctConverter.ConvertFrom(null, provider as CultureInfo, input);
                    return true;
                }
            }
            catch
            {
                // do nothing
            }

            try
            {
                var inputConverter = TypeDescriptor.GetConverter(inputType);
                if (inputConverter != null && inputConverter.CanConvertTo(conversionType))
                {
                    value = inputConverter.ConvertTo(null, provider as CultureInfo, input, conversionType);
                    return true;
                }
            }
            catch
            {
                // do nothing
            }

            // call a possible TryParse method
            object defaultValue = conversionType.IsValueType ? conversionType.Assembly.CreateInstance(conversionType.FullName) : null;
            MethodInfo mi = conversionType.GetMethod("TryParse", BindingFlags.Static | BindingFlags.Public, null, new[] { typeof(string), conversionType.MakeByRefType() }, null);
            if (mi != null && mi.ReturnType == typeof(bool))
            {
                object refValue = defaultValue;
                object[] parameters = { Convert.ToString(input, provider), refValue };
                bool b = (bool)mi.Invoke(null, parameters);
                value = parameters[1];
                return b;
            }

            try
            {
                if (ctConverter != null && !(input is string) && ctConverter.CanConvertFrom(typeof(string)))
                {
                    value = ctConverter.ConvertFrom(null, provider as CultureInfo, Convert.ToString(input, provider));
                    return true;
                }
            }
            catch
            {
                // do nothing
            }

            value = defaultValue;
            return false;
        }

        public static T ChangeType<T>(object input, T defaultValue)
        {
            return ChangeType(input, null, defaultValue);
        }

        public static T ChangeType<T>(object input, IFormatProvider provider, T defaultValue)
        {
            if (TryConvert(input, typeof(T), provider, out object result))
                return (T)result;

            return defaultValue;
        }
    }
}
