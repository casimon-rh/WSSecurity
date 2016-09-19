# WSecurity

Implementación de **Windows Communication Foundation** para el consumo de Servicios Web asegurados en un **Oracle Service Bus**

## Colaboradores
- Eneas Mejía
- Carlos Simón :grin:
- Jorge Ugalde

## Requisitos
- Visual Studio 2013 o superior
  - Net Framework 4.5.1
- Component Pro
  - [Ultimate SAML] (http://www.componentpro.com/saml.net/)
- Certificados de prueba


## Consideraciones
- Especificar rutas de **certificados** en la ubicación marcada con un **#error**
 ```c#
 namespace Client
{
    public partial class WindowsClient : Form
    {
        #error Especificar la ubicación de los certificados
        static X509Certificate2 privateCer = new X509Certificate2(@"Ruta .p12 o pfx", "Contraseña");
        static X509Certificate2 publicCer = new X509Certificate2(@"Ruta .cer");
        //...
    }

}
 ```
- Especificar el **issuer** correcto en la ubicación marcada con un **#error**
```c#
  private Assertion CreateAssertion()
        {
            // Este se obtiene con el OAM
            Assertion assertion = new Assertion();
            assertion.Id = "_" + Guid.NewGuid().ToString();
            assertion.IssueInstant = DateTime.UtcNow;
			#error Especificar issuer
            assertion.Issuer = new Issuer("www.example.com.mx", null, null, SamlNameIdentifierFormat.Entity, null);
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

```
Especificar la **url del endpoint** en la ubicación marcada con un **#error**
```c#
		private void cmdGo_Click(object sender, EventArgs e)
        {
			#error especificar url del endpoint
            EndpointAddress adress =
                new EndpointAddress(new Uri("http://192.168.0.1/testService"), EndpointIdentity.CreateDnsIdentity("jasper2"));
            var factory = new ChannelFactory<FechasPortType>("BindingOSB", adress);
            SamlAssertionClientCredentials saml = new SamlAssertionClientCredentials(new SamlAssertionInfo(CreateAssertion()));
		}
```


- Especificar la **url del endpoint** en el archivo **App.Config**
```xml 
	<client>
      <endpoint address="http://192.168.0.1/testService" binding="customBinding" bindingConfiguration="BindingOSB" name="BindingOSB" contract="ServiceReference1.FechasPortType">
        <identity>
          <dns value="jasper2"/>
        </identity>
      </endpoint>
    </client>
```
- Especificar rutas de **logs** en el archivo **App.Config**
```xml
<sharedListeners>
      <add initializeData="%Ruta de Decarga%\WSSecurityAsymExample\Client\Logs\Tracelog.svclog" 
        type="System.Diagnostics.XmlWriterTraceListener, System, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" 
        name="ServiceModelTraceListener" traceOutputOptions="Timestamp">
        <filter type=""/>
      </add>
      <add initializeData="%Ruta de Decarga%\WSecurity\Client\Logs\Messages.xml" 
        type="System.Diagnostics.XmlWriterTraceListener, System, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" 
        name="ServiceModelMessageLoggingListener" traceOutputOptions="Timestamp">
        <filter type=""/>
      </add>
    </sharedListeners>
```
    
