# Integração — modo biblioteca

Uso embutido em uma aplicação Spring Boot que precisa consultar em memória os certificados das ACs vigentes da ICP-Brasil.

## 1. Dependência

```xml
<dependency>
    <groupId>br.gov.go.saude</groupId>
    <artifactId>icpbrasil-truststore</artifactId>
    <version>0.0.1-SNAPSHOT</version>
</dependency>
```

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

A API de consumo é a classe estática `Cache`:

```java
import br.gov.go.saude.truststore.icpbrasil.service.Cache;
import java.security.cert.X509Certificate;
import java.util.Map;

X509Certificate cert = Cache.getCertificateBySki(ski);          // null se não encontrado
boolean valido       = Cache.isCacheValid();                     // false se cache ainda não pronto ou expirado
Map<String, X509Certificate> todos  = Cache.getAllCertificates();
Map<String, X509Certificate> raizes = Cache.getRootCertificates();
```

Exemplo de uso típico:

```java
import br.gov.go.saude.truststore.icpbrasil.service.Cache;
import org.springframework.stereotype.Service;
import java.security.cert.X509Certificate;

@Service
public class ValidacaoAssinaturaService {

    public boolean caConhecida(String ski) {
        return Cache.isCacheValid() && Cache.getCertificateBySki(ski) != null;
    }

    public X509Certificate buscarCA(String ski) {
        return Cache.getCertificateBySki(ski);
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
| `icpbrasil-truststore.rest.enabled` | `false` | **Manter `false`** em modo biblioteca — o endpoint HTTP é para modo server |
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
