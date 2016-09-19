using System;
using System.Collections.Generic;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MySecurityBE.Saml2
{
    class SamlTokenProvider : SecurityTokenProvider
    {
        SamlAssertionInfo samlInfo;

        public SamlTokenProvider(SamlAssertionInfo samlInfo)
            : base()
        {
            if (samlInfo == null)
            {
                throw new ArgumentNullException("samlInfo");
            }
            this.samlInfo = samlInfo;
        }

        //A REVISAR AQUI ESTA EL PROBLEMA
        //https://github.com/Duikmeester/WF_WCF_Samples/blob/master/WCF/Extensibility/Security/SamlTokenProvider/CS/client/SamlSecurityTokenProvider.cs
        protected override SecurityToken GetTokenCore(TimeSpan timeout)
        {
            SecurityToken result = new SamlToken(this.samlInfo);
            //return  new GenericXmlSecurityToken()
            return result;

        }
    }
}
