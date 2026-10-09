# Quero atualizar as raízes confiáveis

Para mantenedores: o que fazer quando o ITI troca a CA do seu site ou quando surge uma nova raiz
ICP-Brasil. Toda mudança exige nova release, porque nenhuma âncora é configurável. O papel de
cada âncora está em [segurança](seguranca.md#em-quem-cada-conexão-confia).

## Onde as âncoras ficam no código

| Âncora | Onde |
|---|---|
| Raízes do TLS do ITI (ISRG X1 e X2) | PEM em `icpbrasil-truststore-core/src/main/resources/tls/iti/`; SHA-256 em `ItiTlsAnchors.FINGERPRINTS` |
| Restrição do AIA do TLS do ITI (`i.lencr.org`) | Código do download do acervo |
| Raízes ICP-Brasil | SHA-256 em `RaizesFixadas.PRODUCAO` |

## Caso 1: o ITI trocou de CA

1. Confira a cadeia nova:

   ```bash
   echo | openssl s_client -connect acraiz.icpbrasil.gov.br:443 -servername acraiz.icpbrasil.gov.br -showcerts
   ```

2. Baixe a raiz da cadeia na página oficial da CA, por HTTPS (nunca da URL AIA, que é HTTP).
3. Confira o fingerprint SHA-256 com o publicado na página oficial:

   ```bash
   openssl x509 -in RAIZ.pem -noout -fingerprint -sha256
   ```

4. Copie o PEM para `tls/iti/` e adicione o fingerprint a `ItiTlsAnchors.FINGERPRINTS`.
5. Se a nova CA servir as intermediárias fora de `i.lencr.org`, altere também a restrição do AIA.
6. Siga o [checklist](#checklist).

## Caso 2: nova raiz ICP-Brasil

1. Confira o fingerprint SHA-256 no DOU/ITI (nunca só no ZIP do acervo).
2. Acrescente-o a `RaizesFixadas.PRODUCAO`, com comentário da versão da hierarquia.
3. Siga o [checklist](#checklist).

## Checklist

1. `./mvnw verify`
2. Com rede: `./mvnw verify -Pintegration-tests`
3. Registre a mudança no CHANGELOG.
4. [Publique a release](../MAINTAINERS.md#publicando-uma-nova-versão).

## Veja também

- [Monitoramento](monitorar.md): o detalhe `raizesNaoFixadas` e os logs que disparam este procedimento
