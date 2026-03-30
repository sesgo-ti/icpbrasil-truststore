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

- Na inicialização, a lib verifica se o acervo de ACs já existe no `base-dir`. Se não, baixa do ITI.
- A cada 2 horas (padrão), compara o hash remoto com o local e sincroniza se houver atualização.
- O cache em memória é populado automaticamente — nenhum código adicional é necessário.

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
  └─ verifica diretório local
       ├─ acervo ausente → baixa do ITI (ZIP com ACs vigentes + hash SHA-512)
       └─ acervo presente → valida integridade e carrega ACs no cache

a cada 2h (TrustStoreScheduler)
  └─ compara hash remoto (ITI) com hash local
       ├─ igual → nenhuma ação
       └─ diferente → baixa acervo atualizado e recarrega cache
```
