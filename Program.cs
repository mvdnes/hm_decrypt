using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace hmailserver_password
{
    class Program
    {
        static int Main(string[] args)
        {
            if (args.Length < 2 || (args[0] != "enc" && args[0] != "dec"))
            {
                Console.WriteLine("Usage: enc|dec <input>");
                return 1;
            }

            var cipher = new BlowFishCipher();
            if (args[0] == "enc")
            {
                try
                {
                    var output = cipher.EncodeString(args[1]);
                    Console.WriteLine(output);
                }
                catch (ArgumentException e)
                {
                    Console.WriteLine(e.Message);
                    return 2;
                }
            }
            else if (args[0] == "dec")
            {
                try {
                    var output = cipher.DecodeString(args[1]);
                    Console.WriteLine(output);
                }
                catch (ArgumentException e)
                {
                    Console.WriteLine(e.Message);
                    return 2;
                }
            }

            return 0;
        }
    }
}
