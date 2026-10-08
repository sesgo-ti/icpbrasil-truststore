## Gestão das âncoras TLS do download do acervo

Objetivo: manter as raízes em que o `SSLContext` interno confia para baixar o acervo de ACs
vigentes do ITI (`acraiz.icpbrasil.gov.br`).

### Conjuntos de confiança

| Conjunto | Origem | Para que serve |
|---|---|---|
| Âncoras TLS do download do ITI | PEM ISRG Root X1 e X2 em `core/src/main/resources/tls/iti/`, fixados por SHA-256 em `ItiTlsAnchors.FINGERPRINTS` | `SSLContext` interno, usado **apenas** para baixar o ZIP e o hash do acervo |
| Intermediárias do TLS do ITI | AIA CA Issuers, restrito a `i.lencr.org` | Candidatas para formar o caminho até as raízes ISRG; nunca são âncoras |
| Acervo ICP-Brasil | ZIP oficial do ITI, validado pelo SHA-512 publicado | Raízes e intermediárias ICP-Brasil servidas por `/certificate` e usadas na validação PKIX |
| Emissores baixados via AIA | Extensão CA Issuers dos certificados validados | Candidatos para **montar** a cadeia; nunca estabelecem confiança |

Nada é adicionado ao `cacerts` nem aplicado à JVM. O endereço do acervo é fixo na biblioteca e
não há propriedade para alterar âncoras ou endereço: mudança exige nova release.

### Sintoma

O download do acervo falha e o log traz `WARN` com o motivo e as URLs de CA Issuers.

### Procedimento: ITI trocou de CA

1. Confira a cadeia nova:

   ```bash
   echo | openssl s_client -connect acraiz.icpbrasil.gov.br:443 -servername acraiz.icpbrasil.gov.br -showcerts
   ```

2. Baixe a raiz da cadeia na página oficial da CA, por HTTPS (nunca da URL AIA, que é HTTP).
3. Confira o fingerprint SHA-256 com o publicado na página oficial:

   ```bash
   openssl x509 -in RAIZ.pem -noout -fingerprint -sha256
   ```

4. Copie o PEM para `icpbrasil-truststore-core/src/main/resources/tls/iti/` e adicione o
   fingerprint a `ItiTlsAnchors.FINGERPRINTS`.
5. Rode `./mvnw verify` e, com rede, `./mvnw verify -Pintegration-tests`.
6. Registre a mudança no CHANGELOG.
7. Publique a release.

Se a nova CA servir as intermediárias fora de `i.lencr.org`, a restrição do AIA também precisa
mudar no código.

## Gestão das raízes ICP-Brasil fixadas

Só as raízes listadas em `RaizesFixadas` (por SHA-256) entram no acervo publicado; o log `ERROR`
`Raízes fora da lista fixada descartadas` e o detalhe `raizesNaoFixadas` do health indicam raiz fora da lista.

### Procedimento: Nova raiz ICP-Brasil

1. Confira o fingerprint SHA-256 no DOU/ITI (nunca só no ZIP do acervo).
2. Acrescente-o a `RaizesFixadas.PRODUCAO`, com comentário da versão da hierarquia.
3. Rode `./mvnw verify -Pintegration-tests`.
4. Registre a mudança no CHANGELOG.
5. Publique a release.
