using System;
using System.Collections.Generic;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.Linq;
using System.ServiceModel;
using System.ServiceModel.Security.Tokens;
using System.Text;
using System.Threading.Tasks;

namespace MySecurityBE.Saml2
{

    //A REVISAR https://msdn.microsoft.com/en-us/library/aa355062(v=vs.110).aspx
    public class CreditCardClientCredentialsSecurityTokenManager : ClientCredentialsSecurityTokenManager
    {
        SamlAssertionClientCredentials samlAssertionClientCredentials;

        public CreditCardClientCredentialsSecurityTokenManager(SamlAssertionClientCredentials creditCardClientCredentials)
            : base(creditCardClientCredentials)
        {
            this.samlAssertionClientCredentials = creditCardClientCredentials;
        }

        public override SecurityTokenProvider CreateSecurityTokenProvider(SecurityTokenRequirement tokenRequirement)
        {
            if (tokenRequirement.TokenType == "urn:oasis:names:tc:SAML:2.0:assertion")
            {
                return new SamlTokenProvider(this.samlAssertionClientCredentials.SamlInfo);
            }
            else if (tokenRequirement is InitiatorServiceModelSecurityTokenRequirement)
            {
                if (tokenRequirement.TokenType == SecurityTokenTypes.X509Certificate)
                {
                    return new X509SecurityTokenProvider(samlAssertionClientCredentials.ServiceCertificate.DefaultCertificate);
                }
            }
            return base.CreateSecurityTokenProvider(tokenRequirement);
        }

        public override SecurityTokenSerializer CreateSecurityTokenSerializer(SecurityTokenVersion version)
        {
            return new SamlAssertionSecurityTokenSerializer(version);
        }

    }
}
