## Gestão das âncoras TLS do download do acervo

Objetivo: incluir, conferir ou substituir os certificados em que o `SSLContext` interno confia para
baixar o acervo de ACs vigentes do ITI (`acraiz.icpbrasil.gov.br`).

### O que este registro é — e o que não é

A biblioteca usa quatro conjuntos de confiança distintos. Este manual trata só do primeiro:

| Conjunto | Origem | Para que serve |
|---|---|---|
| Âncoras TLS do download do ITI | JSON em `icpbrasil-truststore.trusted-certs.dir` (padrão `classpath:registries/certificates`) | `SSLContext` interno do `TrustStoreManager`, usado **apenas** para baixar o ZIP e o hash do acervo |
| Acervo ICP-Brasil | ZIP oficial do ITI, validado pelo SHA-512 publicado | Raízes e intermediárias ICP-Brasil servidas por `/certificate` e usadas na validação PKIX |
| Emissores baixados via AIA | Extensão CA Issuers dos certificados validados | Candidatos para **montar** a cadeia (`CertificateChainResolver`); nunca estabelecem confiança |
| Validação PKIX | Raízes do acervo como âncoras | `PkixCertificateValidator`: caminho até uma raiz do acervo e revogação de cada certificado |

O registro TLS não é aplicado à JVM: nada é adicionado ao `cacerts`, e não é preciso usar
`-Djavax.net.ssl.trustStore`. Os downloads de AIA, OCSP e CRL usam o truststore padrão da JVM,
protegidos pela política de download (veja a seção "Contexto SSL e segurança" do README).

### Como o registro é carregado

- São lidos os arquivos `*.json` **diretamente** no diretório configurado; subdiretórios são
  ignorados.
- De cada JSON, só o campo `pem` é usado para montar a âncora. Os demais campos (`sourceUrl`,
  `fingerprintSha256`, `subject`, `issuer`, `notBefore`, `notAfter`, `format`) são metadados de
  conferência. No registro embutido, o teste `EmbeddedTrustedCertsTest` garante que eles
  correspondem ao certificado do `pem`.
- Todo certificado do registro vira âncora (inclusive intermediárias). O alias no KeyStore é
  `sha256-<fingerprint do DER>`: certificados com o mesmo CN coexistem, e duplicatas idênticas
  entram uma vez. O alias é só um rótulo, não um critério de confiança.
- Apontar `icpbrasil-truststore.trusted-certs.dir` para outro diretório (`file:` ou
  `classpath:`) **substitui** o registro embutido.

### Qual certificado registrar para o ITI

`acraiz.icpbrasil.gov.br` envia apenas o próprio certificado no handshake TLS, sem a intermediária,
e o JDK não busca emissores via AIA. Por isso o registro precisa conter a **intermediária** que
emitiu o certificado do servidor; registrar só a raiz não forma caminho algum. Para identificá-la:

```bash
# Emissor atual e URL da intermediária (campo "CA Issuers")
echo | openssl s_client -connect acraiz.icpbrasil.gov.br:443 -servername acraiz.icpbrasil.gov.br 2>/dev/null \
  | openssl x509 -noout -issuer -ext authorityInfoAccess
```

Como a Let's Encrypt alterna entre as intermediárias de uma mesma geração, registre todas as da
geração em uso (em 2026: YE1–YE3 e YR1–YR3, publicadas em `https://letsencrypt.org/certificates/`).

Pré-requisitos: OpenSSL 3 (`openssl version`), `curl` e `jq`.

---

### Passo 1 — Obter os valores oficiais para conferência

Na página oficial do emissor (para a Let's Encrypt, `https://letsencrypt.org/certificates/`),
anote o fingerprint SHA-256 do certificado. Baixe o certificado dessa página, por HTTPS — não da
URL AIA, que é HTTP simples.

### Passo 2 — Baixar o PEM

`CERTNAME` é um nome simples para o certificado (ex.: `letsencrypt_ye1`).

```bash
curl -sSfL "https://letsencrypt.org/certs/gen-y/int-ye1.pem" -o "CERTNAME.pem"
openssl x509 -in "CERTNAME.pem" -noout -subject -issuer -dates
```

### Passo 3 — Conferir fingerprint e metadados

```bash
openssl x509 -in "CERTNAME.pem" -noout -fingerprint -sha256
openssl x509 -in "CERTNAME.pem" -noout -text | grep -A1 -E "Basic Constraints|Key Usage"
```

- O fingerprint deve coincidir **integralmente** com o oficial do Passo 1 (ignore caixa e `:`).
  Havendo divergência, descarte o arquivo e recomece.
- `Basic Constraints` deve trazer `CA:TRUE`; `Subject`, `Issuer` e validade devem ser os
  publicados.

### Passo 4 — Montar o JSON de registro

```bash
jq -n \
  --arg sourceUrl "https://letsencrypt.org/certs/gen-y/int-ye1.pem" \
  --arg fp "$(openssl x509 -in CERTNAME.pem -noout -fingerprint -sha256 | cut -d= -f2)" \
  --arg subject "$(openssl x509 -in CERTNAME.pem -noout -subject -nameopt multiline | sed -n 's/^ *commonName *= //p')" \
  --arg issuer "$(openssl x509 -in CERTNAME.pem -noout -issuer -nameopt multiline | sed -n 's/^ *commonName *= //p')" \
  --arg notBefore "$(openssl x509 -in CERTNAME.pem -noout -startdate -dateopt iso_8601 | cut -d= -f2 | tr ' ' 'T')" \
  --arg notAfter "$(openssl x509 -in CERTNAME.pem -noout -enddate -dateopt iso_8601 | cut -d= -f2 | tr ' ' 'T')" \
  --arg pem "$(cat CERTNAME.pem)" \
  '{sourceUrl: $sourceUrl, fingerprintSha256: $fp, format: "pem", issuer: $issuer,
    subject: $subject, notBefore: $notBefore, notAfter: $notAfter, pem: $pem}' > CERTNAME.json
```

(`-dateopt iso_8601` exige OpenSSL 3.)

Exemplo real (`registries/certificates/letsencrypt_ye1.json`, com o PEM abreviado):

```json
{
  "sourceUrl": "https://letsencrypt.org/certs/gen-y/int-ye1.pem",
  "fingerprintSha256": "A2:37:2D:06:43:1E:97:16:36:5E:EE:D4:7E:C0:20:35:14:97:D1:82:FC:C0:38:E4:57:E5:81:68:A0:3C:AC:07",
  "format": "pem",
  "issuer": "Root YE",
  "subject": "YE1",
  "notBefore": "2025-09-03T00:00:00Z",
  "notAfter": "2028-09-02T23:59:59Z",
  "pem": "-----BEGIN CERTIFICATE-----\nMIICizCCAhGgAwIBAgIQXd1w3TH4Achc..."
}
```

### Passo 5 — Registrar

- **Registro embutido (nova versão da biblioteca):** copie o JSON para
  `icpbrasil-truststore-core/src/main/resources/registries/certificates/` (no mesmo nível dos
  demais, sem subpasta), remova os JSON de hierarquias que o ITI deixou de usar e rode
  `./mvnw verify` — o `EmbeddedTrustedCertsTest` confere os metadados e o caminho do certificado
  TLS do ITI (atualize o snapshot em `src/test/resources/tls/` se o certificado do servidor
  mudou). Com rede, `./mvnw verify -Pintegration-tests` baixa do ITI real com o registro.
- **Sem nova versão (produção):** coloque os JSON num diretório e aponte
  `icpbrasil-truststore.trusted-certs.dir` para ele (ex.: `file:/etc/icpbrasil-truststore/tls`).
  O diretório inteiro substitui o registro embutido: inclua todos os certificados necessários.

### Passo 6 — Checklist

- [ ] Fingerprint SHA-256 local igual ao oficial.
- [ ] `CA:TRUE`, `Subject`, `Issuer` e validade conferidos.
- [ ] JSON com `pem` e metadados coerentes, no nível do diretório configurado (sem subpasta).
- [ ] `./mvnw verify` verde (registro embutido) ou download do acervo bem-sucedido no ambiente
      (log `Adicionados N certificados confiáveis ao TrustStore interno` seguido da sincronização).
- [ ] Mudança registrada no CHANGELOG (registro embutido) ou no controle de mudanças do ambiente.
