# Gestão das raízes confiáveis

Objetivo: manter atualizadas as raízes fixadas na biblioteca, as do TLS do download do ITI e as do acervo ICP-Brasil.

Sinais de falha (logs, health): [manual de monitoramento](manual-monitoramento.md).

## O que é fixado e onde

| O quê | Onde | Para que serve |
|---|---|---|
| Raízes ISRG X1 e X2 | PEM em `icpbrasil-truststore-core/src/main/resources/tls/iti/`; SHA-256 em `ItiTlsAnchors.FINGERPRINTS` | Âncoras do `SSLContext` interno, usado **apenas** para baixar o ZIP e o hash do acervo |
| Intermediárias do TLS do ITI | AIA CA Issuers, restrito a `i.lencr.org` | Candidatas ao caminho até as raízes ISRG; nunca são âncoras |
| Raízes ICP-Brasil | SHA-256 em `RaizesFixadas.PRODUCAO` | Só as raízes listadas entram no acervo publicado e na validação PKIX |

Nada é adicionado ao `cacerts` nem aplicado à JVM. O endereço do acervo é fixo na biblioteca e
não há propriedade para alterar âncoras ou endereço: toda mudança exige nova release.

## Procedimento: ITI trocou de CA

1. Confira a cadeia nova:

   ```bash
   echo | openssl s_client -connect acraiz.icpbrasil.gov.br:443 -servername acraiz.icpbrasil.gov.br -showcerts
   ```

2. Baixe a raiz da cadeia na página oficial da CA, por HTTPS (nunca da URL AIA, que é HTTP).
3. Confira o fingerprint SHA-256 com o publicado na página oficial:

   ```bash
   openssl x509 -in RAIZ.pem -noout -fingerprint -sha256
   ```

4. Copie o PEM para `icpbrasil-truststore-core/src/main/resources/tls/iti/` e adicione o fingerprint a `ItiTlsAnchors.FINGERPRINTS`.
5. Se a nova CA servir as intermediárias fora de `i.lencr.org`, altere também a restrição do AIA no código.
6. Valide e publique (checklist abaixo).

## Procedimento: nova raiz ICP-Brasil

1. Confira o fingerprint SHA-256 no DOU/ITI (nunca só no ZIP do acervo).
2. Acrescente-o a `RaizesFixadas.PRODUCAO`, com comentário da versão da hierarquia.
3. Valide e publique (checklist abaixo).

## Checklist

1. `./mvnw verify`.
2. Com rede: `./mvnw verify -Pintegration-tests`.
3. Registrar a mudança no CHANGELOG.
4. Publicar a release ([MAINTAINERS.md](../MAINTAINERS.md#publicando-uma-nova-versão)).
