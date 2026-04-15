# Exemplo de integração — modo biblioteca

## Caso típico: sincronização automática

O consumidor quer que a aplicação mantenha atualizado o acervo de certificados das Autoridades Certificadoras (ACs) vigentes da ICP-Brasil e consiga consultá-los por SKI em tempo de execução.

### 1. Dependência

```xml
<dependency>
    <groupId>br.gov.go.saude.fhir</groupId>
    <artifactId>trust-store-icpbrasil</artifactId>
    <version>0.0.1-SNAPSHOT</version>
</dependency>
```

### 2. Configuração mínima (`application.yml`)

```yaml
truststore-icpbrasil:
  storage:
    type: filesystem
  filesystem:
    base-dir: .data/truststore-icpbrasil
```

Isso é tudo. A partir daqui:

- Na inicialização, a lib executa um **bootstrap síncrono**: verifica se o acervo de ACs já existe no `base-dir`; se não, baixa do ITI e popula o cache **antes** de o Spring declarar o contexto "Started".
- A cada 2 horas (padrão), compara o hash remoto com o local e sincroniza se houver atualização.
- O cache em memória é populado automaticamente — nenhum código adicional é necessário.

---

### 2.1 Bootstrap síncrono — implicações para o consumidor

O bootstrap bloqueia o startup até o cache estar pronto. Isso elimina a race condition em que requisições chegavam antes do cache ser populado (e falhavam com `CERT.NOT-TRUSTED-ROOT`), mas tem três consequências práticas:

**1. O startup pode demorar alguns segundos a mais no primeiro boot** — tempo do download ZIP + hash + validação de integridade. Execuções subsequentes reutilizam o cache no disco e sobem instantaneamente.

**2. Se a rede estiver indisponível no primeiro boot, a aplicação falha com `IllegalStateException` (fail-fast ativo por padrão)**. Esse é o comportamento correto em produção: é preferível a aplicação não subir a subir servindo 404 para certificados válidos.

**3. Testes que sobem `@SpringBootTest` precisam lidar com isso.** Três opções, em ordem de preferência:

```yaml
# src/test/resources/application.yaml
truststore-icpbrasil:
  bootstrap:
    enabled: false   # desliga o bootstrap em testes
```

Se o teste precisa do cache populado, mocke o `Downloader` (padrão já usado em `IcpBrasilCertificateProviderTest`) e mantenha `bootstrap.enabled=true` — o bootstrap vai popular via mock.

Último recurso (só em dev local):

```yaml
truststore-icpbrasil:
  bootstrap:
    enabled: true
    fail-fast: false   # não aborta startup; loga erro e sobe com cache vazio
```

**Checklist do consumidor em modo lib:**

- [ ] `application.yaml` do host mantém defaults do bootstrap (`enabled=true`, `fail-fast=true`).
- [ ] `src/test/resources/application.yaml` desabilita o bootstrap (`enabled=false`) ou mocka `Downloader`.
- [ ] Observabilidade: os logs `Iniciando bootstrap síncrono ...` e `Bootstrap síncrono concluído com sucesso em X ms` devem aparecer no startup. Se não aparecerem, o bean não foi registrado (checar `@ComponentScan` do host ou se `bootstrap.enabled=false` foi herdado).

---

### 3. Consultar um certificado pelo SKI

Quando precisar verificar se um determinado certificado pertence a uma AC da cadeia de confiança ICP-Brasil, use `Cache` e consulte pelo SKI:

```java
import br.gov.go.saude.fhir.truststore.icpbrasil.service.Cache;
import org.springframework.stereotype.Service;
import java.security.cert.X509Certificate;

@Service
public class ValidacaoAssinaturaService {

    public boolean caConhecida(String ski) {
        return Cache.isCacheValid() && Cache.getCertificateBySki(ski) != null;
    }

    public X509Certificate buscarCA(String ski) {
        return Cache.getCertificateBySki(ski); // null se não encontrado ou cache inválido
    }
}
```

> `Cache` é uma classe com métodos estáticos — não é necessário injetá-la via `@Autowired`.

---

### O que acontece por baixo (sem código adicional)

```
inicialização
  └─ TrustStoreBootstrap (ApplicationRunner, síncrono)
       └─ verifica diretório local
            ├─ acervo ausente → baixa do ITI (ZIP com ACs vigentes + hash SHA-512)
            └─ acervo presente → valida integridade
       └─ popula Cache em memória indexado por SKI
       └─ se Cache.isCacheValid() = false e fail-fast = true → aborta startup
  └─ Spring declara "Started" (cache já populado)

a cada 2h (TrustStoreScheduler, com initialDelay = 2h para não competir com bootstrap)
  └─ compara hash remoto (ITI) com hash local
       ├─ igual → nenhuma ação
       └─ diferente → baixa acervo atualizado e recarrega cache
```
