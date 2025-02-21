using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AccordionMode
{
    class Program
    {
        static void Main(string[] args)
        {
            ThreeBranch threeBranchAlg = new ThreeBranch();
            byte[] pText = new byte[48];
            byte[] key= new byte[16];
            byte[] tag = new byte[16];
            for (int i = 0; i < pText.Length; i++)
                pText[i] = (byte)i;
            for (int i = 0; i < key.Length; i++)
                key[i] = (byte)i;
            for (int i = 0; i < tag.Length; i++)
                tag[i] = (byte)i;

            var output=threeBranchAlg.Encipher(pText, key, tag);

            Console.WriteLine(Commons.ByteArrayToString(output));
        }
    }
}
