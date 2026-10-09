# Guia do mantenedor

Local **único** para informações operacionais de manutenção do projeto.

## Chave GPG de release

| Campo | Valor |
|---|---|
| Key ID | `566A199A481E3355` |
| Fingerprint | `8EF6 6D44 5A97 6C0A 2C3B 4FB5 566A 199A 481E 3355` |
| UID | `SES-GO TI <ti-ses.saude@goias.gov.br>` |
| Criada em | 2026-08-31 |
| **Expira em** | **2028-08-30** |

### Onde a chave pública está publicada

A chave foi publicada em **dois** keyservers:

1. **keyserver.ubuntu.com** — HKP tradicional
2. **keys.openpgp.org** — keyserver moderno (VKS)

> Não existe "keyserver do Maven Central": o Sonatype Central apenas **consulta**
> keyservers públicos para validar assinaturas (ele suporta `keyserver.ubuntu.com`,
> `keys.openpgp.org` e `pgp.mit.edu`). Qualquer operação na chave (renovação,
> revogação) deve ser propagada aos **dois** servidores acima.

### Renovar a expiração (fazer antes de 2028-08-30)

```bash
gpg --edit-key 566A199A481E3355
# no prompt: expire → definir novo prazo (ex.: 2y) → save
# se pedir, repetir para a subchave: key 1 → expire → save

# Propagar aos DOIS keyservers:
gpg --keyserver keyserver.ubuntu.com --send-keys 566A199A481E3355
gpg --keyserver keys.openpgp.org  --send-keys 566A199A481E3355
```

A renovação **não** altera a chave privada — os secrets do GitHub continuam válidos.
Se a chave for **substituída** (novo par), atualizar os secrets da organização
(`MAVEN_GPG_PRIVATE_KEY`, `MAVEN_GPG_PASSPHRASE`) e os fingerprints neste arquivo
e no [SECURITY.md](SECURITY.md).

### Revogar a chave (comprometimento ou perda)

Quando revogar: vazamento da chave privada ou da passphrase, perda de controle
da chave, ou desligamento do detentor sem transição segura.

O certificado de revogação foi gerado na criação da chave
(`~/.gnupg/openpgp-revocs.d/8EF66D445A976C0A2C3B4FB5566A199A481E3355.rev`)
e deve estar guardado no cofre da equipe. Ele funciona **mesmo sem a chave privada**.

```bash
# 1. Preparar o certificado: o arquivo vem com um ':' de segurança no início
#    da linha BEGIN — remova o ':'

# 2. Importar a revogação sobre a chave no chaveiro local
gpg --import 8EF66D445A976C0A2C3B4FB5566A199A481E3355.rev

# 3. Publicar a chave (agora marcada como REVOGADA) nos DOIS keyservers
gpg --keyserver keyserver.ubuntu.com --send-keys 566A199A481E3355
gpg --keyserver keys.openpgp.org  --send-keys 566A199A481E3355
```

Depois da revogação:

1. **Gerar novo par** (RSA 4096, e-mail institucional) e publicar nos dois keyservers.
2. **Rotacionar os secrets da organização**: `MAVEN_GPG_PRIVATE_KEY`, `MAVEN_GPG_PASSPHRASE`.
3. **Atualizar fingerprints** neste arquivo e no [SECURITY.md](SECURITY.md).
4. **Comunicar** via GitHub Security Advisory (e nas notas do release seguinte),
   informando a data da revogação e o fingerprint da chave nova.
5. Guardar novo certificado de revogação + backup da privada + passphrase no cofre.

Notas importantes:

- Chaves **nunca são apagadas** de keyserver — apenas marcadas como revogadas.
- Artefatos já publicados no Maven Central são imutáveis e permanecem assinados
  pela chave antiga; a semântica correta para consumidores é: assinaturas feitas
  **antes** da data de revogação continuam auditáveis, novas assinaturas não.

## Alerta agendado das raízes ICP-Brasil e do TLS do ITI

O workflow `.github/workflows/raizes-icp.yml` roda diariamente (por volta de 09:17 UTC), a cada push
na `main` e sob demanda. Ele baixa o acervo real do ITI pelo TLS fixado e compara as raízes com
`RaizesFixadas`. Qualquer falha abre a issue "Alerta ICP-Brasil/TLS do ITI"; com ela aberta, novas
falhas viram comentários. Feche-a ao resolver.

Ao receber a issue, confirme no DOU/ITI antes de alterar qualquer lista:

- **Raiz nova ou fora da lista**: atualizar `RaizesFixadas` e publicar release.
- **Raiz fixada ausente**: se a retirada for oficial, removê-la de `RaizesFixadas` e publicar release.
- **Falha de TLS no download**: se o ITI trocou de CA, atualizar `ItiTlsAnchors` e publicar release.
- **Sem mudança oficial** (acervo adulterado ou ITI instável): investigar.

**Limitação**: o GitHub desativa workflows agendados após 60 dias sem commits no repositório.
Reative em Actions → o workflow → *Enable workflow*.

## Secrets da organização (GitHub → sesgo-ti → Actions)

| Secret | Conteúdo |
|---|---|
| `MAVEN_CENTRAL_USERNAME` | username do user token do Sonatype Central |
| `MAVEN_CENTRAL_TOKEN` | password do user token |
| `MAVEN_GPG_PRIVATE_KEY` | chave privada ASCII-armored (`gpg --armor --export-secret-keys`) |
| `MAVEN_GPG_PASSPHRASE` | passphrase da chave |

Visibilidade restrita ao repositório `icpbrasil-truststore`.

## Publicando uma nova versão

A publicação é **automatizada por tag** no workflow [release.yml](.github/workflows/release.yml),
em três jobs:

1. **`verificar`** (sem secrets, `contents: read`): valida que a tag `vX.Y.Z` corresponde à
   versão dos POMs (sem `-SNAPSHOT`), compila e testa todos os módulos, gera o SBOM, extrai as
   notas da seção `[X.Y.Z]` do CHANGELOG (falha se ela não existir ou estiver vazia) e monta os
   assets: o executável REST, o SBOM e o `SHA256SUMS`.
2. **`publicar-central`** (environment `release`, com os secrets): assina com GPG e publica
   **parent POM + `core` + `spring-boot-starter`**. O `rest` (fat jar) não vai ao Central.
3. **`github-release`** (environment `release`, `contents: write`): cria a GitHub Release com as
   notas e os assets, ou a atualiza se já existir.

Todas as actions são fixadas por SHA completo, com a versão em comentário; o Dependabot
(`github-actions`) propõe as atualizações.

### Pré-requisitos (uma única vez, já configurados)

- Secrets na organização GitHub (tabela acima), com o user token gerado em
  [central.sonatype.com](https://central.sonatype.com) → Account → Generate User Token.
- Namespace `br.gov.go.saude` **verificado** no Sonatype Central.
- Chave GPG publicada nos dois keyservers (seção acima).
- **Environment `release`** (Settings → Environments) com *required reviewers* (ao menos um
  mantenedor além de quem cria a tag) e *deployment branches and tags* restrito a tags `v*`.
- **Ruleset de tags `v*`** (Settings → Rules): criação restrita aos mantenedores, com
  atualização e remoção bloqueadas.

### Passo a passo do release

```bash
# 1. Garanta main atualizada e CI verde
#    Confira em Actions que o workflow "Alerta de raízes ICP-Brasil e TLS do ITI" está ativo
#    e sem issue de alerta aberta; confira a validade das raízes ISRG (`ItiTlsAnchors`)
#    e a lista de `RaizesFixadas`
git checkout main && git pull

# 2. Atualize o CHANGELOG.md: mova o conteúdo de [Unreleased]
#    para uma nova seção [X.Y.Z] com a data — ela vira as notas da GitHub Release. Commite

# 3. Fixe a versão de release (remove -SNAPSHOT em todos os módulos)
./mvnw versions:set -DnewVersion=X.Y.Z && ./mvnw versions:commit
git commit -am "chore: release X.Y.Z"

# 4. Valide localmente ANTES da tag (build completo, sources e Javadoc; sem assinar)
./mvnw clean verify -Prelease -Dgpg.skip=true

# 5. Tag ANOTADA e push — a tag dispara o workflow de publicação
git tag -a vX.Y.Z -m "vX.Y.Z"
git push origin main vX.Y.Z

# 6. Acompanhe o workflow em Actions e aprove os jobs do environment `release`;
#    ao final ele cria a GitHub Release. O job do Central conclui assim que o Central
#    valida o bundle: o artefato pode ainda não estar disponível nesse momento

# 7. Reabra o ciclo de desenvolvimento
./mvnw versions:set -DnewVersion=X.Y.(Z+1)-SNAPSHOT && ./mvnw versions:commit
git commit -am "chore: inicia desenvolvimento X.Y.(Z+1)-SNAPSHOT" && git push
```

O workflow grava nos artefatos a data do commit da tag (`project.build.outputTimestamp`), de modo
que qualquer rebuild do mesmo commit gera JARs idênticos; não é preciso editar essa data no
`pom.xml`.

### Se o release falhar

- Falha no workflow **antes** de publicar: corrija, apague a tag
  (`git push origin :refs/tags/vX.Y.Z`), refaça a partir do passo 4.
- Falha **após** publicar no Central: a versão é imutável — publique um
  patch `X.Y.(Z+1)`. Nunca reutilize um número de versão.
- Falha **só na GitHub Release** (Central já publicado): rode o workflow Release
  manualmente (Actions → Release → Run workflow) informando a tag. Ele refaz `verificar` e
  `github-release` sem republicar no Central; se a Release existir, atualiza notas e assets.

### Verificação pós-release

```bash
# Assets da GitHub Release
gh release download vX.Y.Z -R sesgo-ti/icpbrasil-truststore && sha256sum -c SHA256SUMS
```

```bash
curl -s "https://central.sonatype.com/artifact/br.gov.go.saude/icpbrasil-truststore-spring-boot-starter/X.Y.Z" -o /dev/null -w '%{http_code}\n'
```
