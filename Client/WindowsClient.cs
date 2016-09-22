using System;
using System.Security.Cryptography.X509Certificates;
using System.Windows.Forms;
using System.Threading;
using System.ServiceModel;
using System.IdentityModel.Tokens;
using ComponentPro.Saml2;
using System.Linq;
using System.ServiceModel.Channels;
using MySecurityBE;
using Client.ServiceReference1;
using System.Xml;
using System.Collections.Generic;
using System.Security.Cryptography.Xml;
using System.Security.Cryptography;
using System.IO;
using MySecurityBE.Binding;
using MySecurityBE.Saml2;
using System.ServiceModel.Security;

namespace Client
{
    public partial class WindowsClient : Form
    {
        public WindowsClient()
        {
            InitializeComponent();
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            Application.ThreadException += new ThreadExceptionEventHandler(Application_ThreadException);
        }

        void Application_ThreadException(object sender, ThreadExceptionEventArgs e)
        {
            string err = e.Exception.Message + Environment.NewLine + e.Exception.StackTrace;
            if (e.Exception.InnerException != null)
                err += Environment.NewLine + e.Exception.InnerException.Message + Environment.NewLine + e.Exception.InnerException.StackTrace;
            txtRet.Text = err;
        }

        private Assertion CreateAssertion()
        {
            // Este se obtiene con el OAM
            Assertion assertion = new Assertion();
            assertion.Id = "_" + Guid.NewGuid().ToString();
            assertion.IssueInstant = DateTime.UtcNow;
#error Especificar issuer
            assertion.Issuer = new Issuer("www.example.mx", null, null, SamlNameIdentifierFormat.Entity, null);
            assertion.Conditions = new Conditions(DateTime.UtcNow, DateTime.UtcNow.AddMinutes(5));
            assertion.Subject = new Subject(new NameId("DEAA9255")
            {
                Format = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
            })
            {
                SubjectConfirmations = new List<SubjectConfirmation>()
                {
                    new SubjectConfirmation("urn:oasis:names:tc:SAML:2.0:cm:sender-vouches")
                }
            };

            return assertion;

        }

        public static X509Certificate2 GetCertificate(StoreName storeName, StoreLocation location, String thumbprint)
        {
            var store = new X509Store(storeName, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly);
            var cert = store.Certificates.OfType<X509Certificate2>()
                .FirstOrDefault(x => x.Thumbprint == thumbprint);
            store.Close();
            return cert;
        }

        private void cmdGo_Click(object sender, EventArgs e)
        {
#error especificar url del endpoint
            EndpointAddress adress = new EndpointAddress(new Uri("http://localhost"), EndpointIdentity.CreateDnsIdentity("jasper2"));


            var factory = new ChannelFactory<FechasPortType>(Service.getCustomBinding(), adress);

            SamlAssertionClientCredentials saml = new SamlAssertionClientCredentials(new SamlAssertionInfo(CreateAssertion()));
            X509Certificate2 privateCer = Service.getCertificate();

            factory.Endpoint.Behaviors.Remove<System.ServiceModel.Description.ClientCredentials>();
            factory.Endpoint.Behaviors.Add(saml);

            factory.Credentials.SupportInteractive = false;
            factory.Credentials.ClientCertificate.Certificate = privateCer;
            factory.Credentials.ServiceCertificate.DefaultCertificate = privateCer;
            factory.Credentials.ServiceCertificate.Authentication.CertificateValidationMode = X509CertificateValidationMode.None;
            factory.Credentials.ServiceCertificate.Authentication.RevocationMode = X509RevocationMode.NoCheck;


            try
            {
                var proxy = factory.CreateChannel();
                var ret = proxy.consultarFechaHoraBD(new consultarFechaHoraBDRequest(""));
                txtRet.Text = ret.consultaFechaHoraBDResponse.ToString();

            }
            catch (Exception ex)
            {

                MessageBox.Show(ex.Message);
            }


        }
    }
}
