# Guia do mantenedor

Local **único** para informações operacionais de manutenção do projeto.
Documentos voltados a contribuidores e consumidores apenas apontam para cá.

## Chave GPG de release

| Campo | Valor |
|---|---|
| Key ID | `566A199A481E3355` |
| Fingerprint | `8EF6 6D44 5A97 6C0A 2C3B 4FB5 566A 199A 481E 3355` |
| UID | `SES-GO TI <ti-ses.saude@goias.gov.br>` |
| Criada em | 2026-08-31 |
| **Expira em** | **2028-08-30** |

### Onde a chave pública está publicada

A chave foi publicada em **dois** keyservers (verificado):

1. **keyserver.ubuntu.com** — HKP tradicional
2. **keys.openpgp.org** — keyserver moderno (VKS)

> Não existe "keyserver do Maven Central": o Sonatype Central apenas **consulta**
> keyservers públicos para validar assinaturas (ele suporta `keyserver.ubuntu.com`,
> `keys.openpgp.org` e `pgp.mit.edu`). Qualquer operação na chave (renovação,
> revogação) deve ser propagada aos **dois** servidores acima.

### Renovar a expiração (fazer antes de 2028-08-30 — lembrete sugerido: 2028-08-01)

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
#    da linha BEGIN — remova o ':' conforme instrui o comentário do próprio arquivo

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

## Secrets da organização (GitHub → sesgo-ti → Actions)

| Secret | Conteúdo |
|---|---|
| `MAVEN_CENTRAL_USERNAME` | username do user token do Sonatype Central |
| `MAVEN_CENTRAL_TOKEN` | password do user token |
| `MAVEN_GPG_PRIVATE_KEY` | chave privada ASCII-armored (`gpg --armor --export-secret-keys`) |
| `MAVEN_GPG_PASSPHRASE` | passphrase da chave |

Visibilidade restrita ao repositório `icpbrasil-truststore`.

## Publicando uma nova versão

A publicação no Maven Central é **automatizada por tag**: o workflow
[release.yml](.github/workflows/release.yml) compila, assina com GPG e publica os
módulos `core` e `autoconfigure` (o módulo `rest` é artefato de deploy e não é
publicado — `skipPublishing=true`).

### Pré-requisitos (uma única vez, já configurados)

- Secrets na organização GitHub (tabela acima), com o user token gerado em
  [central.sonatype.com](https://central.sonatype.com) → Account → Generate User Token.
- Namespace `br.gov.go.saude` **verificado** no Sonatype Central.
- Chave GPG publicada nos dois keyservers (seção acima).

### Passo a passo do release

```bash
# 1. Garanta main atualizada e CI verde
git checkout main && git pull

# 2. Atualize o CHANGELOG.md: mova o conteúdo de [Unreleased]
#    para uma nova seção [X.Y.Z] com a data, e commite

# 3. Fixe a versão de release (remove -SNAPSHOT em todos os módulos)
./mvnw versions:set -DnewVersion=X.Y.Z && ./mvnw versions:commit
git commit -am "chore: release X.Y.Z"

# 4. Valide localmente ANTES da tag (build completo + assinatura)
./mvnw clean verify -Prelease

# 5. Tag e push — a tag dispara o workflow de publicação
git tag vX.Y.Z
git push origin main vX.Y.Z

# 6. Acompanhe o workflow em Actions; ao final ele cria o GitHub Release
#    e o artefato fica disponível no Central em até ~30 min

# 7. Reabra o ciclo de desenvolvimento
./mvnw versions:set -DnewVersion=X.Y.(Z+1)-SNAPSHOT && ./mvnw versions:commit
git commit -am "chore: inicia desenvolvimento X.Y.(Z+1)-SNAPSHOT" && git push
```

### Se o release falhar

- Falha no workflow **antes** de publicar: corrija, apague a tag
  (`git push origin :refs/tags/vX.Y.Z`), refaça a partir do passo 4.
- Falha **após** publicar no Central: a versão é imutável — publique um
  patch `X.Y.(Z+1)`. Nunca reutilize um número de versão.

### Verificação pós-release

```bash
curl -s "https://central.sonatype.com/artifact/br.gov.go.saude/icpbrasil-truststore-autoconfigure/X.Y.Z" -o /dev/null -w '%{http_code}\n'
```
