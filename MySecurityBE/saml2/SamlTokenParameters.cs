using System;
using System.Collections.Generic;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.Linq;
using System.ServiceModel.Security.Tokens;
using System.Text;
using System.Threading.Tasks;

namespace MySecurityBE.Saml2
{
    public class SamlAssertionTokenParameters : SecurityTokenParameters
    {
        public SamlAssertionTokenParameters()
        {
        }

        protected SamlAssertionTokenParameters(SamlAssertionTokenParameters other)
            : base(other)
        {
        }

        protected override SecurityTokenParameters CloneCore()
        {
            return new SamlAssertionTokenParameters(this);
        }

        protected override void InitializeSecurityTokenRequirement(SecurityTokenRequirement requirement)
        {
            requirement.TokenType = "urn:oasis:names:tc:SAML:2.0:assertion";
            return;
        }

        protected override bool HasAsymmetricKey
        {
            get { return true; }
        }

        protected override bool SupportsClientAuthentication
        {
            get { return true; }
        }

        protected override bool SupportsClientWindowsIdentity
        {
            get { return false; }
        }

        protected override bool SupportsServerAuthentication
        {
            get { return false; }
        }

        public object Constants { get; private set; }

        protected override SecurityKeyIdentifierClause CreateKeyIdentifierClause(SecurityToken token, SecurityTokenReferenceStyle referenceStyle)
        {
            if (referenceStyle == SecurityTokenReferenceStyle.Internal)
            {
                return token.CreateKeyIdentifierClause<LocalIdKeyIdentifierClause>();
            }
            else
            {
                throw new NotSupportedException("External references are not supported for credit card tokens");
            }
        }
    }
}
