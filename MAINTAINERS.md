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
Se a chave for **substituída** (novo par), atualizar os secrets do environment `release`
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
2. **Rotacionar os secrets do environment `release`**: `MAVEN_GPG_PRIVATE_KEY`, `MAVEN_GPG_PASSPHRASE`.
3. **Atualizar fingerprints** neste arquivo e no [SECURITY.md](SECURITY.md).
4. **Comunicar** via GitHub Security Advisory (e nas notas do release seguinte),
   informando a data da revogação e o fingerprint da chave nova.
5. Guardar novo certificado de revogação + backup da privada + passphrase no cofre.

Notas importantes:

- Chaves **nunca são apagadas** de keyserver — apenas marcadas como revogadas.
- Artefatos já publicados no Maven Central são imutáveis e permanecem assinados
  pela chave antiga; a semântica correta para consumidores é: assinaturas feitas
  **antes** da data de revogação continuam auditáveis, novas assinaturas não.

## Secrets de publicação (environment `release`)

| Secret | Conteúdo |
|---|---|
| `MAVEN_CENTRAL_USERNAME` | username do user token do Sonatype Central |
| `MAVEN_CENTRAL_TOKEN` | password do user token |
| `MAVEN_GPG_PRIVATE_KEY` | chave privada ASCII-armored (`gpg --armor --export-secret-keys`) |
| `MAVEN_GPG_PASSPHRASE` | passphrase da chave |

Configurar no environment protegido `release`, não em escopo acessível ao job
`verify`. Se já existirem na organização, restringir/remover o acesso direto deste
repositório após a migração. Os nomes acima são o contrato do workflow, não uma
confirmação de que os secrets ou suas permissões foram provisionados.

## Publicando uma nova versão

A publicação no Maven Central é disparada por tag: o workflow
[release.yml](.github/workflows/release.yml) verifica o commit sem secrets e, após
aprovação do environment, publica **parent POM + core + autoconfigure**. O REST
participa dos testes, mas não do reactor de publicação. A candidata `0.0.1`,
fechada localmente em **2026-09-08**, ainda não foi publicada nem recebeu tag.

### Pré-requisitos externos (confirmar manualmente antes de qualquer tag)

- Namespace `br.gov.go.saude` verificado no Sonatype Central e token com autorização para publicá-lo.
- Secrets da tabela acima no environment `release`, com chave GPG válida e chave pública consultável nos keyservers. Os registros históricos deste guia não substituem essa conferência.
- Environment `release` com revisores obrigatórios, impedimento de autoaprovação e restrição às tags de release. Declarar `environment: release` no YAML **não cria essas proteções**; sem configuração manual, não há garantia de aprovação humana.
- Rulesets protegendo `main` (revisão e CI obrigatório) e criação/alteração/exclusão de tags `v*`, restrita aos mantenedores autorizados. O gate exige ancestralidade na `origin/main`, mas não substitui rulesets nem revisão do código do workflow.
- Confirmar que `0.0.1` ainda não existe no Central. Sucesso local não confirma namespace, token, assinatura, validação remota ou disponibilidade da versão.

### Verificação local sem publicação

```bash
./mvnw -B -ntp clean verify -Prelease -Dgpg.skip=true
bash scripts/verify-release.sh v0.0.1
```

Executar na raiz com JDK 21, Bash e Python 3 (biblioteca padrão). A tag passada
ao script é apenas texto para comparação: ele não consulta nem cria tags.
O script gera POMs efetivos via Maven, compara as quatro versões e referências ao
parent, rejeita versões SNAPSHOT, confere URLs SCM sem sufixos de módulos e
`scm.tag`, e inspeciona classes, fontes, Javadoc e LICENSE nos JARs binários/fontes.

`target/release-inspection/unsigned-bundle.zip` é um **bundle de inspeção local**:
3 POMs, 2 JARs binários, 2 sources, 2 Javadoc e 36 checksums MD5/SHA-1/SHA-256/SHA-512.
Não contém REST nem assinaturas `.asc`. Ele não é enviado a lugar algum e **não é
um bundle validado pelo publicador ou pelo Central**. Não o utilize para upload.

O `central-publishing-maven-plugin` está fixado em `0.11.0`, versão estável mais
recente confirmada no [metadata Maven](https://repo.maven.apache.org/maven2/org/sonatype/central/central-publishing-maven-plugin/maven-metadata.xml)
e nas [notas oficiais](https://central.sonatype.org/publish/publish-portal-maven/#release-notes)
em 2026-09-08. A `0.9.0` corrigiu o tratamento por módulo de `skipPublishing`;
`excludeArtifacts` usa **artifactId**, não GAV nem padrões de versão, e exclui
também os anexos do REST. A seleção explícita `-pl ... -am` é a separação principal.

**Não usar `deploy` nem `central-publishing:publish` como dry-run.** Apesar da
descrição de `skipPublishing` na documentação, o código-fonte publicado da `0.11.0`
(`PublishMojo.processRelease` / `postProcessRelease`) filtra os artefatos com essa
flag antes do staging, mas o pós-processamento pode enviar staging residual.
Por isso o caminho local não chama o publicador, nem mesmo com settings vazios.
A composição real produzida pelo plugin, assinaturas e aceitação pelo Central
permanecem pendentes de uma execução futura explicitamente autorizada.

### Fluxo autorizado de release

1. Revisar a candidata, todos os POMs/referências ao parent, exemplos, `scm.tag` e changelog. Para outra versão, atualizar esses valores em conjunto.
2. Executar a verificação local acima e obter CI verde; integrar em `main` somente após revisão e autorização.
3. Somente com autorização específica, criar e enviar a tag anotada `vX.Y.Z` do commit revisado. Isso dispara publicação remota; não faz parte da preparação local.
4. O job `verify`, sem secrets de publicação, exige formato estrito `vMAJOR.MINOR.PATCH`, sem zeros iniciais/sufixos, tag apontando ao commit exato do evento e ancestralidade na `origin/main`. Compila/testa todos os módulos e compara a tag com todos os POMs efetivos antes de liberar `publish`.
5. Aprovar o environment `release` após conferir os pré-requisitos. O job `publish` recompila o mesmo SHA em runner separado, sem cache compartilhado, assina e publica com o comando abaixo. O limite do job é 60 minutos, superior aos 1800 segundos de espera do plugin, com margem para build/upload.
6. O job separado `github-release` só recebe `contents: write` após sucesso da publicação. Os demais usam `contents: read`, e todos os checkouts usam `persist-credentials: false`. As actions estão fixadas por SHA verificado no GitHub.

Comando **remoto e privilegiado**, exclusivo da etapa autorizada de publicação:

```bash
./mvnw -B -ntp -Prelease \
  -pl icpbrasil-truststore-core,icpbrasil-truststore-autoconfigure -am clean deploy
```

### Se o release falhar

- Falha ou timeout não prova ausência de upload: conferir o deployment no Portal antes de qualquer nova tentativa. Não mover nem apagar tags automaticamente.
- Se já publicado no Central, a versão é imutável: corrigir em nova versão. Se apenas o GitHub Release falhou, recuperar essa etapa sem republicar no Central.
- Auditoria de dependências/SBOM/SCA, reprodutibilidade e distribuição do REST continuam fora desta preparação; o build verde não é atestado de ausência de vulnerabilidades.

### Verificação pós-release

```bash
curl -s "https://central.sonatype.com/artifact/br.gov.go.saude/icpbrasil-truststore-autoconfigure/X.Y.Z" -o /dev/null -w '%{http_code}\n'
```
