# Integração — modo biblioteca

Uso embutido em uma aplicação Spring Boot que precisa consultar em memória os certificados das ACs vigentes da ICP-Brasil.

## 1. Dependência

> A `0.0.1` ainda não foi publicada. Estas coordenadas antecipam a primeira
> release; para experimentação local, instale parent e bibliotecas com
> `./mvnw -pl icpbrasil-truststore-core,icpbrasil-truststore-autoconfigure -am install`.

```xml
<dependency>
    <groupId>br.gov.go.saude</groupId>
    <artifactId>icpbrasil-truststore-autoconfigure</artifactId>
    <version>0.0.1</version>
</dependency>
```

> O `autoconfigure` traz o `icpbrasil-truststore-core` transitivamente. Para storage S3,
> adicione também `software.amazon.awssdk:s3` e `software.amazon.awssdk:apache-client`
> (são `optional` no autoconfigure).

Auto-configuração: nenhuma anotação `@Import` ou registro manual de beans é necessário.

## 2. Configuração mínima

```yaml
icpbrasil-truststore:
  storage:
    type: filesystem
  filesystem:
    base-dir: .data/icpbrasil-truststore
```

Na inicialização, o runner revalida o acervo local e tenta atualização pelo ITI.
Ele termina antes do `ApplicationReadyEvent` e do retorno de `SpringApplication.run()`,
mas o servidor HTTP pode aceitar requisições antes. Outros beans e seus inicializadores
também podem consultar cache vazio; a biblioteca não instala uma barreira global de consumo.
Se o cache continuar inválido, `bootstrap.fail-fast=true` encerra o contexto.
Um acervo local válido pode sustentar a operação até seu prazo original mesmo com falha remota.

Para aplicações web, adicione `spring-boot-starter-actuator` (opcional na lib) e
configure explicitamente os grupos no YAML do consumidor:

```yaml
management:
  endpoints:
    web:
      exposure:
        include: health
  endpoint:
    health:
      show-details: never
      probes:
        enabled: true
      group:
        readiness:
          include: readinessState,trustStoreCache
        liveness:
          include: livenessState
```

O balanceador/orquestrador deve respeitar `/actuator/health/readiness` (503 enquanto
a aplicação não aceita tráfego ou o cache está indisponível). Liveness não depende
do acervo nem de ITI/S3. Health não faz I/O; reflete o snapshot e o relógio do cache.
Detalhes operacionais e proteção da porta de gerenciamento estão no
[manual de monitoramento](manual-monitoramento.md).

## 3. Consultar certificados

A API de consumo é o bean `Cache`, exposto pela auto-configuração — injete-o
como qualquer dependência (a leitura é pública; a escrita é restrita ao pipeline
interno da lib, preservando a cadeia de custódia do acervo):

```java
import br.gov.go.saude.truststore.icpbrasil.service.Cache;
import org.springframework.stereotype.Service;
import java.security.cert.X509Certificate;
import java.util.Map;

@Service
public class ValidacaoAssinaturaService {

    private final Cache cache;

    public ValidacaoAssinaturaService(Cache cache) {
        this.cache = cache;
    }

    public boolean caConhecida(String ski) {
        return cache.getCertificateBySki(ski) != null;
    }

    public X509Certificate buscarCA(String ski) {
        return cache.getCertificateBySki(ski); // null se ausente ou acervo indisponível
    }

    public Map<String, X509Certificate> raizes() {
        return cache.getRootCertificates();                       // cópia defensiva
    }
}
```

Se for necessário distinguir acervo indisponível de SKI ausente, use
`cache.lookupCertificate(ski)`: `available()` e `certificate()` são capturados no
mesmo snapshot e instante. Não combine `isCacheValid()` com uma leitura posterior
para decidir entre 503 e 404. A validade não revoga cópias já entregues.

## 4. Variáveis de configuração relevantes

| Propriedade | Default | Quando mudar |
|---|---|---|
| `icpbrasil-truststore.storage.type` | `filesystem` | Usar `s3` quando o cache precisa ser compartilhado entre instâncias |
| `icpbrasil-truststore.filesystem.base-dir` | — | Sempre definir (caminho do cache em disco) |
| `icpbrasil-truststore.bootstrap.enabled` | `true` | **Desligar apenas em testes** que sobem `@SpringBootTest` sem rede |
| `icpbrasil-truststore.bootstrap.fail-fast` | `true` | Mudar para `false` só em dev local onde a indisponibilidade do ITI é aceitável |
| `icpbrasil-truststore.scheduling.enabled` | `true` | Desligar só em testes |
| `icpbrasil-truststore.refresh-interval-hours` | `2` | Ajustar se precisar de sincronização mais/menos frequente |

Demais propriedades (rede, revogação, cadeia, política de download) têm defaults adequados — consulte o [README](../README.md) se precisar ajustar.

## 5. Testes

Ao subir o `ApplicationContext` em testes, desabilite o bootstrap para não depender da rede:

```yaml
# src/test/resources/application.yaml
icpbrasil-truststore:
  bootstrap:
    enabled: false
  scheduling:
    enabled: false
```

Alternativa: manter o bootstrap ligado e mockar o `Downloader` — assim o cache é populado a partir de um ZIP de teste. Veja `IcpBrasilCertificateProviderTest` no repositório para o padrão.
