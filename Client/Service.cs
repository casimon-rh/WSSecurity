using CertFixEscapedComma;
using Spring.Context.Support;
using System;
using System.Collections.Generic;
using System.Linq;
using System.ServiceModel.Channels;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography.X509Certificates;

namespace Client
{
    public static class Service
    {
        private static X509Certificate2 cert;
        public static CustomBinding getCustomBinding()
        {
            List<BindingElement> lbe = new List<BindingElement>();
            lbe.Add(ContextRegistry.GetContext().GetObject("AsymetricSecurityBE") as BindingElement);
            lbe.Add(new CertRefEncodingBindingElement(new TextMessageEncodingBindingElement(), ContextRegistry.GetContext().GetObject("Encoder") as MessageEncoder));
            lbe.Add(new HttpTransportBindingElement());

            CustomBinding co = new CustomBinding(lbe.ToArray());
            return co;
        }

        public static X509Certificate2 getCertificate()
        {
            if (cert == null)
                cert = ContextRegistry.GetContext().GetObject("Certificate") as X509Certificate2;
            return cert;
        }
    }
}
