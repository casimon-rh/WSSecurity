using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MySecurityBE.cifrados
{
    public interface ICifrado<T>
    {
        byte[] descifrar(String text);
        T Key { set; get; }

        byte[] cifrar(byte[] text);
    }
}
