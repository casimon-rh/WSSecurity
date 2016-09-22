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


- Especificar ruta del **certificado**  en el archivo **App.Config**
```xml
<object type="System.Security.Cryptography.X509Certificates.X509Certificate2,System" id="Certificate">
    <constructor-arg value="Ruta" />
    <constructor-arg value="Contraseña" />
</object>

```
- Especificar Namespaces del **response**  en el archivo **App.Config**
```xml
<object type="CertFixEscapedComma.CertRefEncoder,MySecurityBE" id="Encoder" singleton="false">
    <property name="certificado" ref="Certificate"/>
    <property name="cypher" ref="Cypher"/>
    <property name="namespaces">
        <dictionary key-type="string" value-type="string">
            <entry key="valid" value="https://"/>
            <entry key="invalid" value="https://"/>
        </dictionary>
    </property>
</object>

```
    
