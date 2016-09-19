using ComponentPro.Saml2;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.Linq;
using System.ServiceModel.Security.Tokens;
using System.Text;
using System.Threading.Tasks;

namespace MySecurityBE.Saml2
{
    public class SamlAssertionInfo
    {
        public Assertion SamlAssertion { get; set; }
        public DateTime ExpirationDate { get; internal set; }

        public SamlAssertionInfo(Assertion assertion)
        {
            this.SamlAssertion = assertion;
        }
    }
}
