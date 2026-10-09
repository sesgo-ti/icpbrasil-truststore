# Trust Store ICP-Brasil

[![Build](https://github.com/sesgo-ti/icpbrasil-truststore/actions/workflows/ci.yml/badge.svg)](https://github.com/sesgo-ti/icpbrasil-truststore/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Maven Central](https://img.shields.io/maven-central/v/br.gov.go.saude/icpbrasil-truststore)](https://central.sonatype.com/artifact/br.gov.go.saude/icpbrasil-truststore)

Biblioteca Spring Boot que mantém atualizado o acervo de Autoridades Certificadoras (ACs) vigentes
da ICP-Brasil e valida certificados contra ele. Também pode rodar como serviço REST.

## O que faz

- Baixa o acervo oficial do ITI, confere o SHA-512 e o mantém atualizado em background.
- Guarda o acervo num diretório local ou num bucket S3.
- Valida certificados (caminho PKIX até as raízes ICP-Brasil e revogação OCSP/CRL).
- Expõe o estado do acervo no `/actuator/health`.

## Requisitos

- Java 21
- Spring Boot 3.5.x

## Início rápido

### Como biblioteca

1. Adicione a dependência:

```xml
<dependency>
    <groupId>br.gov.go.saude</groupId>
    <artifactId>icpbrasil-truststore-spring-boot-starter</artifactId>
    <version>0.0.3</version>
</dependency>
```

2. Informe onde gravar o acervo no `application.yml` (única propriedade obrigatória):

```yaml
icpbrasil-truststore:
  filesystem:
    base-dir: .data/icpbrasil-truststore
```

3. Injete o validador e use:

```java
ValidationResult resultado = pkixCertificateValidator.validate(certificado);
```

Guia completo: [usar como biblioteca](docs/usar-como-biblioteca.md).

### Como serviço

Baixe o `icpbrasil-truststore-rest-<versão>.jar` da
[GitHub Release](https://github.com/sesgo-ti/icpbrasil-truststore/releases) e execute:

```bash
java -jar icpbrasil-truststore-rest-<versão>.jar --icpbrasil-truststore.filesystem.base-dir=/data/truststore
```

Guia completo: [subir o serviço](docs/subir-servico.md).

## Documentação

| Quero... | Guia |
|---|---|
| Usar a biblioteca na minha aplicação | [Usar como biblioteca](docs/usar-como-biblioteca.md) |
| Validar um certificado | [Validação de certificados](docs/validar-certificado.md) |
| Consultar só a revogação (OCSP/CRL) | [Revogação](docs/verificar-revogacao.md) |
| Montar a cadeia de um certificado | [Montagem de cadeia](docs/montar-cadeia.md) |
| Gravar o acervo num diretório local | [Armazenamento em diretório](docs/armazenamento-filesystem.md) |
| Gravar o acervo no S3 | [Armazenamento no S3](docs/armazenamento-s3.md) |
| Subir o serviço REST | [Subir o serviço](docs/subir-servico.md) |
| Consultar os endpoints do serviço | [Endpoints REST](docs/endpoints-rest.md) |
| Monitorar (health, probes, logs) | [Monitoramento](docs/monitorar.md) |
| Ajustar timeouts, caches e limites | [Referência de configuração](docs/configuracao.md) |
| Liberar a rede e entender a confiança e a proteção contra SSRF | [Segurança e rede](docs/seguranca.md) |
| Conferir a autenticidade dos artefatos | [Verificação dos artefatos](docs/verificar-artefatos.md) |
| Atualizar raízes fixadas (mantenedores) | [Atualizar raízes confiáveis](docs/atualizar-raizes-confiaveis.md) |

## Módulos

| Artefato | Uso |
|---|---|
| `icpbrasil-truststore-spring-boot-starter` | Declare este para usar a biblioteca com Spring Boot |
| `icpbrasil-truststore-core` | Lógica sem Spring; vem junto com o starter |
| `icpbrasil-truststore-rest` | Serviço REST; distribuído como JAR executável na GitHub Release |

## Contribuir

Build, testes e fluxo de PR: [CONTRIBUTING.md](CONTRIBUTING.md). Vulnerabilidades:
[SECURITY.md](SECURITY.md). Release e chave GPG: [MAINTAINERS.md](MAINTAINERS.md).

## Licença

[Apache License 2.0](LICENSE)
