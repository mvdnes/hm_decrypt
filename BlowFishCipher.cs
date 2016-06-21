using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace hmailserver_password
{
    public class BlowFishCipher
    {
        uint[] PArray;
        uint[] SBoxes;
        public BlowFishCipher()
        {
            PArray = new uint[18];
            SBoxes = new uint[4*256];
            Initialize(Constants.NOT_SECRET_KEY);
        }

        void Initialize(byte[] key)
        {
            Constants.bf_P.CopyTo(PArray, 0);
            Constants.bf_S.CopyTo(SBoxes, 0);
            for (int i = 0, j = 0; i < Constants.NPASS + 2; ++i, j += 4)
            {
                uint temp = 
                    (uint)key[(j + 0) % key.Length] << 24
                    | (uint)key[(j + 1) % key.Length] << 16
                    | (uint)key[(j + 2) % key.Length] << 8
                    | (uint)key[(j + 3) % key.Length] << 0;
                PArray[i] ^= temp;
            }

            Tuple<uint, uint> xlxr = Tuple.Create(0u, 0u);

            for (int i = 0; i < Constants.NPASS + 2; i += 2)
            {
                xlxr = Encipher(xlxr);
                PArray[i] = xlxr.Item1;
                PArray[i + 1] = xlxr.Item2;
            }
            
            for (int i = 0; i < 4; ++i)
            {
                for (int j = 0; j < 256; j += 2)
                {
                    xlxr = Encipher(xlxr);
                    SBoxes[i * 256 + j] = xlxr.Item1;
                    SBoxes[i * 256 + j + 1] = xlxr.Item2;
                }
            }
        }

        uint Round(uint b, int n)
        {
            //#define S(x,i) (SBoxes[i][x.w.byte##i])
            //#define bf_F(x) (((S(x,0) + S(x,1)) ^ S(x,2)) + S(x,3))
            //#define ROUND(a,b,n) (a.dword ^= bf_F(b) ^ PArray[n])

            uint S0 = SBoxes[0 * 256 + ((b >> 24) & 0xFF)];
            uint S1 = SBoxes[1 * 256 + ((b >> 16) & 0xFF)];
            uint S2 = SBoxes[2 * 256 + ((b >> 8) & 0xFF)];
            uint S3 = SBoxes[3 * 256 + ((b >> 0) & 0xFF)];
            uint bf_F = ((S0 + S1) ^ S2) + S3;
            return bf_F ^ PArray[n];
        }

        Tuple<uint, uint> Encipher(Tuple<uint, uint> xlxr)
        {
            uint xl = xlxr.Item1;
            uint xr = xlxr.Item2;

            xl ^= PArray[0];
            xr ^= Round(xl, 1);
            xl ^= Round(xr, 2);
            xr ^= Round(xl, 3);
            xl ^= Round(xr, 4);
            xr ^= Round(xl, 5);
            xl ^= Round(xr, 6);
            xr ^= Round(xl, 7);
            xl ^= Round(xr, 8);
            xr ^= Round(xl, 9);
            xl ^= Round(xr, 10);
            xr ^= Round(xl, 11);
            xl ^= Round(xr, 12);
            xr ^= Round(xl, 13);
            xl ^= Round(xr, 14);
            xr ^= Round(xl, 15);
            xl ^= Round(xr, 16);
            xr ^= PArray[17];

            return Tuple.Create(xr, xl);
        }

        Tuple<uint, uint> Decipher(Tuple<uint, uint> xlxr)
        {
            uint xl = xlxr.Item1;
            uint xr = xlxr.Item2;

            xl ^= PArray[17];
            xr ^= Round(xl, 16);
            xl ^= Round(xr, 15);
            xr ^= Round(xl, 14);
            xl ^= Round(xr, 13);
            xr ^= Round(xl, 12);
            xl ^= Round(xr, 11);
            xr ^= Round(xl, 10);
            xl ^= Round(xr, 9);
            xr ^= Round(xl, 8);
            xl ^= Round(xr, 7);
            xr ^= Round(xl, 6);
            xl ^= Round(xr, 5);
            xr ^= Round(xl, 4);
            xl ^= Round(xr, 3);
            xr ^= Round(xl, 2);
            xl ^= Round(xr, 1);
            xr ^= PArray[0];

            return Tuple.Create(xr, xl);
        }

        uint GetOutputLength(uint len)
        {
            uint lval = len % 8;
            if (lval != 0)
            {
                return len + 8 - lval;
            }
            else
            {
                return len;
            }
        }

        public byte[] Decode(byte[] input)
        {
            if (input.Length % 8 != 0)
            {
                throw new ArgumentException("Input is not a multiple of 8 bytes");
            }

            byte[] output = new byte[input.Length];
            for (int i = 0; i < input.Length; i += 8)
            {
                uint xl =
                    ((uint)input[i + 3] << 24) |
                    ((uint)input[i + 2] << 16) |
                    ((uint)input[i + 1] << 8) |
                    ((uint)input[i + 0] << 0);
                uint xr =
                    ((uint)input[i + 7] << 24) |
                    ((uint)input[i + 6] << 16) |
                    ((uint)input[i + 5] << 8) |
                    ((uint)input[i + 4] << 0);

                Tuple<uint, uint> xlxr = Tuple.Create(xl, xr);
                xlxr = Decipher(xlxr);
                xl = xlxr.Item1;
                xr = xlxr.Item2;

                output[i + 3] = (byte)((xl >> 24) & 0xFF);
                output[i + 2] = (byte)((xl >> 16) & 0xFF);
                output[i + 1] = (byte)((xl >> 8) & 0xFF);
                output[i + 0] = (byte)((xl >> 0) & 0xFF);
                output[i + 7] = (byte)((xr >> 24) & 0xFF);
                output[i + 6] = (byte)((xr >> 16) & 0xFF);
                output[i + 5] = (byte)((xr >> 8) & 0xFF);
                output[i + 4] = (byte)((xr >> 0) & 0xFF);
            }

            return output;
        }

        public byte[] Encode(byte[] input)
        {
            if (input.Length % 8 != 0)
            {
                throw new ArgumentException("Input is not a multiple of 8 bytes");
            }

            byte[] output = new byte[input.Length];
            for (int i = 0; i < input.Length; i += 8)
            {
                uint xl =
                    ((uint)input[i + 3] << 24) |
                    ((uint)input[i + 2] << 16) |
                    ((uint)input[i + 1] << 8) |
                    ((uint)input[i + 0] << 0);
                uint xr =
                    ((uint)input[i + 7] << 24) |
                    ((uint)input[i + 6] << 16) |
                    ((uint)input[i + 5] << 8) |
                    ((uint)input[i + 4] << 0);

                Tuple<uint, uint> xlxr = Tuple.Create(xl, xr);
                xlxr = Encipher(xlxr);
                xl = xlxr.Item1;
                xr = xlxr.Item2;

                output[i + 3] = (byte)((xl >> 24) & 0xFF);
                output[i + 2] = (byte)((xl >> 16) & 0xFF);
                output[i + 1] = (byte)((xl >> 8) & 0xFF);
                output[i + 0] = (byte)((xl >> 0) & 0xFF);
                output[i + 7] = (byte)((xr >> 24) & 0xFF);
                output[i + 6] = (byte)((xr >> 16) & 0xFF);
                output[i + 5] = (byte)((xr >> 8) & 0xFF);
                output[i + 4] = (byte)((xr >> 0) & 0xFF);
            }

            return output;
        }

        public static byte[] FromHex(string input)
        {
            try {
            var bytes = new byte[input.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                string part = input.Substring(i * 2, 2);
                bytes[i] = Convert.ToByte(part, 16);
            }
            return bytes;
            }
            catch (FormatException e)
            {
                throw new ArgumentException(e.Message);
            }
        }

        public static string ToHex(byte[] input)
        {
            return string.Concat(input.Select(b => b.ToString("x2")));
        }

        public string EncodeString(string input)
        {
            var input_bytes = Encoding.UTF8.GetBytes(input);

            var outlen = GetOutputLength((uint)input_bytes.Length);
            var cipher_input = new byte[outlen];
            for (int i = 0; i < outlen; ++i)
            {
                if (i < input_bytes.Length)
                {
                    cipher_input[i] = input_bytes[i];
                }
                else
                {
                    cipher_input[i] = 0;
                }
            }

            var cipher_output = Encode(cipher_input);
            return ToHex(cipher_output);
        }

        public string DecodeString(string input)
        {
            var cipher_input = FromHex(input);
            var cipher_output = Decode(cipher_input);

            int len = cipher_output.Length;
            while (len > 0 && cipher_output[len-1] == 0)
            {
                len--;
            }

            return Encoding.UTF8.GetString(cipher_output, 0, len);
        }
    }
}
