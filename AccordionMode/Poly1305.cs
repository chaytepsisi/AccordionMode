using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Mpir.NET;

namespace AccordionMode
{
    internal class Poly1305
    {
        public Poly1305()
        {
                
        }

         Calculate()
        {
            //void poly1305_gmpxx(unsigned char*out,
//const unsigned char* r,
//const unsigned char* s,
//const unsigned char* m, unsigned int l)
{
                uint j;
                mpz_t rbar = 0;
                for (j = 0; j < 16; ++j)
                    rbar += ((mpz_t)r[j]) << (8 * j);
                mpz_t h = 0;
                mpz_t p = (((mpz_t)1) << 130) - 5;
                while (l > 0)
                {
                    mpz_t c = 0;
                    for (j = 0; (j < 16) && (j < l); ++j)
                        c += ((mpz_t)m[j]) << (8 * j);
                    c += ((mpz_t)1) << (8 * j);
                    m += j; l -= j;
                    h = ((h + c) * rbar) % p;
                }
                for (j = 0; j < 16; ++j)
                    h += ((mpz_t)s[j]) << (8 * j);
                for (j = 0; j < 16; ++j)
                {
                    mpz_t c = h % 256;
                    h >>= 8;
                out[j] = c.get_ui();
                }
            }

        }
    }
}
