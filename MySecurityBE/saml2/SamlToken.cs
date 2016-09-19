using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MySecurityBE.Saml2
{
    public class SamlToken : SecurityToken
    {
        SamlAssertionInfo samlAssertionInfo;
        DateTime effectiveTime = DateTime.UtcNow;
        string id;
        ReadOnlyCollection<SecurityKey> securityKeys;

        public SamlToken(SamlAssertionInfo samlAssertionInfo) : this(samlAssertionInfo, Guid.NewGuid().ToString()) { }

        public SamlToken(SamlAssertionInfo samlAssertionInfo, string id)
        {
            if (samlAssertionInfo == null)
            {
                throw new ArgumentNullException("samlAssertionInfo");
            }
            if (id == null)
            {
                throw new ArgumentNullException("id");
            }

            this.samlAssertionInfo = samlAssertionInfo;
            this.id = id;
            this.securityKeys = new ReadOnlyCollection<SecurityKey>(new List<SecurityKey>());
        }

        public SamlAssertionInfo SamlAssertionInfo
        {
            get { return this.samlAssertionInfo; }
        }

        public override ReadOnlyCollection<SecurityKey> SecurityKeys
        {
            get { return this.securityKeys; }
        }

        public override DateTime ValidFrom
        {
            get { return this.effectiveTime; }
        }

        public override DateTime ValidTo
        {
            get { return this.samlAssertionInfo.ExpirationDate; }
        }

        public override string Id
        {
            get { return this.id; }
        }
    }
}
