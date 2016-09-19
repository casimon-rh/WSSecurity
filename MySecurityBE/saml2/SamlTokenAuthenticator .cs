using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IdentityModel.Claims;
using System.IdentityModel.Policy;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MySecurityBE.Saml2
{
    public class SamlAssertionTokenAuthenticator : SecurityTokenAuthenticator
    {
        string creditCardsFile;
        public SamlAssertionTokenAuthenticator(string creditCardsFile)
        {
            this.creditCardsFile = creditCardsFile;
        }

        protected override bool CanValidateTokenCore(SecurityToken token)
        {
            return (token is SamlToken);
        }

        protected override ReadOnlyCollection<IAuthorizationPolicy> ValidateTokenCore(SecurityToken token)
        {
            SamlToken creditCardToken = token as SamlToken;

            if (creditCardToken.SamlAssertionInfo.ExpirationDate < DateTime.UtcNow)
            {
                throw new SecurityTokenValidationException("The credit card has expired");
            }
            List<IAuthorizationPolicy> policies = new List<IAuthorizationPolicy>(1);
            return policies.AsReadOnly();
        }

    }
}
