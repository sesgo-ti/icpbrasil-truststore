# Integração — modo biblioteca

Uso embutido em uma aplicação Spring Boot que precisa consultar em memória os certificados das ACs vigentes da ICP-Brasil.

## 1. Dependência

```xml
<dependency>
    <groupId>br.gov.go.saude</groupId>
    <artifactId>icpbrasil-truststore-autoconfigure</artifactId>
    <version>0.0.1-SNAPSHOT</version>
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

Na inicialização, a lib verifica se o acervo de ACs já existe no `base-dir`. Se não, baixa do ITI. O cache em memória é populado **antes** de o Spring declarar o contexto "Started", eliminando qualquer janela em que requisições cheguem com cache vazio.

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
        return cache.isCacheValid() && cache.getCertificateBySki(ski) != null;
    }

    public X509Certificate buscarCA(String ski) {
        return cache.getCertificateBySki(ski);                    // null se não encontrado
    }

    public Map<String, X509Certificate> raizes() {
        return cache.getRootCertificates();                       // cópia defensiva
    }
}
```

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
