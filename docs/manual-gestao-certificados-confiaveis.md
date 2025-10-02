## Baixar e verificar um certificado X.509 para montagem de truststore

Objetivo: definir o processo de baixar um certificado a partir da fonte oficial, verificar sua autenticidade e efetuar registros correspondentes para montagem de truststore apenas com certificados explicitamente identificados e confiáveis.

**Importante**: o fluxo definido é manual e para ser executado manualmente.

Exemplo usado: certificado raiz ISRG Root X1 da Let's Encrypt, disponível em `https://letsencrypt.org/certs/isrgrootx1.pem`.
Este exemplo não é "acidental", pois o portal do ITI (ICP-Brasil) que disponibiliza os certificados vigentes das CAs usa um certificado da Let's Encrypt.
Ou seja, para que uma aplicação possa baixar os certificados das CAs vigentes da ICP-Brasil, ele terá que construir um truststore com o certificado baixado. 
Sem esse passo a segurança pode ser comprometida.

Pré-requisitos
- OpenSSL disponível no PATH (`openssl version`).
- JDK instalado, para `keytool`: `keytool -version`.
- HTTPie, para download: `http --version`.
- HashCorp Vault CLI, quando o HashiCorp Vault (Cofre) for utilizado: `vault --version`.


---

## Obtenção e verificação

### Passo 0 — Considerações sobre exceções
O que fazer
- Em caso de situação excepcional em qualquer um dos passos subsequentes, o processo não é considerado realizado e terá que ser refeito.

Resultado esperado
- Reconhecimento de que falhas impedem a conclusão válida do processo. Adicionalmente, a necessidade de ter que refazer todo o processo.

### Passo 1 — Obter valores para conferência
O que fazer
- Acesse a página oficial do emissor do certificado e anote os valores de referência para comparação posterior (Passos 3 e 4 usarão estes valores). Para Let's Encrypt consulte `https://letsencrypt.org/certificates/`. Neste caso específico são disponibilizados vários "formatos" por meio dos quais esta confirmação pode ser realizada.

Resultado esperado
- Você tem o fingerprint SHA-256 “oficial” do certificado (e, se publicado, o SPKI ou a chave pública/base64 do SPKI). O SPKI inclui o Public Key Algorithm, Modulus e Exponent.

### Passo 2 — Baixar o arquivo PEM a partir da URL oficial
O que fazer
- Baixe o arquivo e salve localmente com nome claro (neste caso, `isrgrootx1.pem`).

```powershell
# Usando PowerShell nativo
Invoke-WebRequest -Uri "https://letsencrypt.org/certs/isrgrootx1.pem" -OutFile ".\isrgrootx1.pem"

# Alternativa (se houver curl real no PATH; no Windows, 'curl' pode ser alias de Invoke-WebRequest)
curl -L "https://letsencrypt.org/certs/isrgrootx1.pem" -o ".\isrgrootx1.pem"

# Alternativa (HTTPie)
http --download "https://letsencrypt.org/certs/isrgrootx1.pem" --output ".\isrgrootx1.pem"
```

Resultado esperado
- Arquivo `isrgrootx1.pem` criado no diretório atual, com tamanho > 0 byte. Verifique se o OpenSSL consegue ler:

```powershell
openssl x509 -in ".\isrgrootx1.pem" -noout -subject
```

### Passo 3 — Calcular o fingerprint SHA-256 do certificado
O que fazer
- Gere o fingerprint SHA-256 localmente. Você pode calcular de duas maneiras equivalentes:

```powershell
# 3.A) Fingerprint direto via OpenSSL (formato HEX com ":" entre bytes)
openssl x509 -in ".\isrgrootx1.pem" -noout -fingerprint -sha256

# 3.B) Hash do certificado em DER (deve bater com 3.A ignorando formatação)
openssl x509 -in ".\isrgrootx1.pem" -outform der -out ".\isrgrootx1.der"
openssl dgst -sha256 ".\isrgrootx1.der"
```

Resultado esperado
- Fingerprint SHA-256 calculado localmente e anotado para validação posterior.

### Passo 4 — Conferir metadados: sujeito, emissor, validade e validar fingerprint
O que fazer
- Exibir os campos principais do certificado (sujeito/issuer/validade) e compare o fingerprint calculado no Passo 3 com o valor oficial (veja Passo 1).

```powershell
# Com OpenSSL (detalhes completos)
openssl x509 -in ".\isrgrootx1.pem" -noout -text | more

# Com keytool (JDK)
keytool -printcert -v -file ".\isrgrootx1.pem"
```

Dica: ao comparar o fingerprint, ignore maiúsculas/minúsculas e separadores (`:` ou espaços). O conteúdo hexadecimal deve coincidir integralmente.

Resultado esperado
- `Subject` e `Issuer` coerentes com o certificado esperado (para raiz autoassinado, geralmente `Issuer == Subject`).
- Período de validade compatível com o publicado. Caso esteja usando o keytool será exibido "Valid from" e "until", o que é equivalente a "Not before" e "Not after", respectivamente.
- Em "Basic Constraints" aparece `CA:TRUE` (por ser um certificado de Autoridade Certificadora raiz/intermediária) e os `Key Usages` são coerentes.
- O fingerprint SHA-256 calculado localmente coincide exatamente com o valor oficial. Se houver divergência, descarte o arquivo baixado e recomece.
- Se todos os valores coincidem, então o certificado é confiável. Nesse caso, os passos seguintes têm como foco preparar dados para o uso posterior do certificado.

---

## Preparação para uso posterior 

Nesse ponto o certificado foi obtido e as validações necessárias para segurança realizadas. O que segue
são passos visando disponibilizar o certificado e outras informações para o consumo posterior do certificado.

### Passo 5 — Calcular o pin de SPKI
O que fazer
- O SPKI (Subject Public Key Info) já está presente no certificado. Aqui, você deve calcular o hash SHA-256 sobre o SPKI em formato DER e codificar o resultado em Base64 — esse é o pin de SPKI usado para pinning em tempo de execução.

```powershell
# Extrai o SPKI (PUBLIC KEY), converte para DER, calcula SHA-256 e codifica em Base64
openssl x509 -in ".\isrgrootx1.pem" -noout -pubkey `
        | openssl pkey -pubin -outform der `
        | openssl dgst -sha256 -binary `
        | openssl enc -base64
```

Resultado esperado
- Você possui o valor do pin de SPKI (SHA-256 do SPKI em Base64) calculado e anotado para registro posterior.

### Passo 6 — Converter para DER e calcular hash
O que fazer
- Converta o PEM para DER e calcule o hash SHA-256 do arquivo DER para verificação futura (o registro formal ocorrerá no Passo 8).

```powershell
openssl x509 -in ".\isrgrootx1.pem" -outform der -out ".\isrgrootx1.der"
openssl dgst -sha256 ".\isrgrootx1.der"
```

Resultado esperado
- Arquivo `isrgrootx1.der` gerado e hash SHA-256 calculado e anotado para registro posterior.

### Passo 7 — Montar o JSON de registro

O que fazer
- Consolidar em um arquivo JSON os dados obtidos e aqueles calculados. Este arquivo será registrado (Passo 8). Monte o JSON garantindo exatidão dos valores.

Sugestão de nome do arquivo
- `isrgrootx1.json` (no mesmo diretório do `isrgrootx1.pem`).

Exemplo de JSON (ilustrativo)
```json
{
        "sourceUrl": "https://letsencrypt.org/certs/isrgrootx1.pem",
        "fingerprintSha256": "AA:BB:...:ZZ",
        "spkiSha256_b64": "RE1JQkJJakFOQmdrcU...",
        "derSha256": "aa bb cc ... zz",
        "format": "pem",
        "issuer": "ISRG Root X1",
        "subject": "ISRG Root X1",
        "notBefore": "2015-06-04T00:00:00Z",
        "notAfter": "2035-06-04T00:00:00Z",
        "pem": "-----BEGIN CERTIFICATE-----\nMIIF...\n-----END CERTIFICATE-----\n"
}
```

Resultado esperado
- Arquivo JSON de registro montado e consistente com os valores verificados.

### Passo 8 — Efetuar registros

O registro dos dados é necessário porque a finalidade destas operações é disponibilizar certificado confiáveis para serem acrescentados a um truststore que, por sua vez, será criado dinamicamente, a partir destes dados devidamente registrados. 

**Importante**: a estratégia não faz uso de certificados no **cacerts** (truststore) que acompanha a JVM.

O que fazer
- Registrar o arquivo JSON no Cofre (HashiCorp Vault), se disponível.
- Registrar o arquivo JSON em diretório (sistema de arquivos) como fallback, quando o Cofre não estiver disponível.

Opção A — Registrar no Cofre (HashiCorp Vault)
- Justificativa: centraliza segredos, controle de acesso e auditoria.
- Ações:
        - Garanta que a auditoria do Cofre esteja habilitada.
        - Defina o caminho padrão (ex.: `kv/certificates/isrg-root-x1`).
        - O payload a ser registrdo é o documento JSON criado anteriormente (Passo 7).

Como registrar no Cofre (HashCorp Vault)
- Use a UI do HashCorp Vault ou a CLI (`vault kv put`) para gravar os campos definidos no JSON do Passo 7 no caminho definido (ex.: `kv/certificates/isrg-root-x1`).
- Garanta que a auditoria do Cofre esteja habilitada e que as políticas de acesso estejam corretas.

Opção B — Fallback: registrar em arquivo (filesystem)
- Justificativa: quando o Cofre não está disponível (ambiente local/offline).
- Ações:
        - Defina um diretório padronizado versionado (ex.: `registries/certificates/`), com subpastas por emissor/nome.
        - Salve apenas o JSON de registro (com `pem`) no diretório. 

Como registrar no filesystem (fallback)
- Crie um diretório padronizado (ex.: `registries/certificates/isrg-root-x1`).
- Salve o JSON de registro montado no Passo 7 como `isrgrootx1.json` no diretório.

Resultado esperado
- Certificado e metadados armazenados de forma segura, com registro auditável completo no Vault; quando indisponível, registro de fallback consistente e versionável no filesystem.

### Passo 9 — Checklist
- [ ] Conseguiu abrir o certificado baixado (`openssl x509 -noout`) sem erros.
- [ ] `Subject`/`Issuer` são os esperados (para raiz, autoassinado).
- [ ] Informações compatíveis com a informação oficial.
- [ ] Fingerprint SHA-256 local = fingerprint oficial (sem diferenças).
- [ ] SPKI pin calculado (Passo 5), 
- [ ] Objeto JSON construído (Passo 7) 
- [ ] Objeto JSON registrado (Passo 8).
- [ ] Auditoria registrada indicando adição do certificado (quem, data e skpi)

---

## Montagem do truststore

- Recuperar todos os objetos JSON registrados em `certificates`, seja no Cofre ou no sistema de arquivos.
- Para cada objeto JSON deve ser recuperado o certificado correspondente e inserido em um truststore (KeyStore em Java) criado para esta finalidade.
