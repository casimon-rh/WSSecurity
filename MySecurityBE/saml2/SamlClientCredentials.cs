using System;
using System.Collections.Generic;
using System.IdentityModel.Selectors;
using System.Linq;
using System.ServiceModel.Description;
using System.Text;
using System.Threading.Tasks;

namespace MySecurityBE.Saml2
{
    public class SamlAssertionClientCredentials : ClientCredentials
    {
        SamlAssertionInfo samlInfo;

        public SamlAssertionClientCredentials(SamlAssertionInfo samlInfo)
            : base()
        {
            if (samlInfo == null)
            {
                throw new ArgumentNullException("samlInfo");
            }

            this.samlInfo = samlInfo;
        }

        public SamlAssertionInfo SamlInfo
        {
            get { return this.samlInfo; }
        }

        protected override ClientCredentials CloneCore()
        {
            return new SamlAssertionClientCredentials(this.samlInfo);
        }

        public override SecurityTokenManager CreateSecurityTokenManager()
        {
            return new SamlAssertiondClientCredentialsSecurityTokenManager(this);
        }
    }
}
