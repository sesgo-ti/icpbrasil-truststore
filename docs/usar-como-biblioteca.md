# Quero usar a biblioteca na minha aplicação

Para aplicações Spring Boot que precisam do acervo de ACs da ICP-Brasil em memória.

## 1. Adicione a dependência

```xml
<dependency>
    <groupId>br.gov.go.saude</groupId>
    <artifactId>icpbrasil-truststore-spring-boot-starter</artifactId>
    <version>0.0.3</version>
</dependency>
```

O starter se configura sozinho: não é preciso `@Import` nem registrar beans. Todos os componentes
citados nos guias (`PkixCertificateValidator`, `RevocationService`, `CertificateChainResolver`,
`Cache`) já estão disponíveis para injeção.

## 2. Escolha onde gravar o acervo

- [Diretório local](armazenamento-filesystem.md) (padrão)
- [S3](armazenamento-s3.md)

## 3. Use

| Quero... | Use | Guia |
|---|---|---|
| Saber se um certificado é confiável | `PkixCertificateValidator` | [Validação](validar-certificado.md) |
| Saber só se um certificado foi revogado | `RevocationService` | [Revogação](verificar-revogacao.md) |
| Montar a cadeia de um certificado | `CertificateChainResolver` | [Montagem de cadeia](montar-cadeia.md) |
| Buscar uma AC pelo SKI | `Cache` | abaixo |

Buscar uma AC pelo SKI (hexadecimal minúsculo):

```java
Cache.Lookup resultado = cache.lookupCertificate(ski);
if (!resultado.available()) {
    // acervo ainda não carregado ou expirado
} else if (resultado.certificate() == null) {
    // SKI não está no acervo
}
```

Se o acervo tiver mais de um certificado com o mesmo SKI (AC reemitida com a mesma chave),
`lookupCertificate` devolve o preferido: o autoassinado, depois o de maior `notAfter` e, por fim,
o de menor fingerprint SHA-256. `cache.getCertificatesBySki(ski)` devolve todos, e
`cache.getRootCertificates()` devolve as raízes. O `Cache` é só leitura para a aplicação: o acervo
só é alterado pela própria biblioteca, a partir do download verificado.

## 4. Testes sem rede

Em testes que sobem o contexto Spring, desligue a carga e a atualização do acervo:

```yaml
# src/test/resources/application.yaml
icpbrasil-truststore:
  bootstrap:
    enabled: false
  scheduling:
    enabled: false
```

Para testar com o acervo carregado sem acessar o ITI, mantenha o bootstrap ligado e substitua o
`Downloader` por um mock que devolva um ZIP de teste (padrão usado em
`IcpBrasilCertificateProviderTest`).

## Veja também

- [Monitoramento](monitorar.md): readiness no Kubernetes e health do acervo
- [Referência de configuração](configuracao.md)
