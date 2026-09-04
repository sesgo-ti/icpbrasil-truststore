# Contribuindo

Obrigado pelo interesse em contribuir com o **icpbrasil-truststore**!

## Pré-requisitos

- JDK 21 (Temurin recomendado)
- Não é necessário instalar Maven — use o wrapper (`./mvnw`)

## Build e testes

```bash
./mvnw verify
```

Os testes de integração (marcados com `@Tag("integration")`) dependem de rede externa
(repositório do ITI) e **não** rodam no build padrão. Para executá-los:

```bash
./mvnw verify -Pintegration-tests
```

O relatório de cobertura JaCoCo é gerado por módulo em `<módulo>/target/site/jacoco/index.html`.

## Dependências

O Dependabot abre PR semanal para atualizações do Maven e das GitHub Actions.
Para checar manualmente se algo ficou desatualizado fora desse ciclo:

```bash
./mvnw versions:display-dependency-updates
```

## Padrão de commits

Usamos [Conventional Commits](https://www.conventionalcommits.org/pt-br/) com mensagens
em **português**, em uma linha. Exemplos:

```
feat: adiciona verificação de revogação via CRL
fix: corrige parse de bundle PKCS#7 com encoding PEM
docs: atualiza instruções de configuração do S3
```

## Fluxo de Pull Request

1. Crie uma branch a partir de `main`.
2. Faça as alterações com commits no padrão acima.
3. Garanta que `./mvnw verify` está verde localmente.
4. Abra o PR contra `main` e aguarde o CI (GitHub Actions) passar.

## Vulnerabilidades de segurança

Não abra issues públicas para vulnerabilidades. Siga as instruções do
[SECURITY.md](SECURITY.md) para reporte responsável.

## Publicando uma nova versão (mantenedores)

A publicação no Maven Central é **automatizada por tag**: o workflow
[release.yml](.github/workflows/release.yml) compila, assina com GPG e publica os
módulos `core` e `autoconfigure` (o módulo `rest` é artefato de deploy e não é
publicado — `skipPublishing=true`).

### Pré-requisitos (uma única vez, já configurados)

- Secrets na organização GitHub: `MAVEN_CENTRAL_USERNAME`, `MAVEN_CENTRAL_TOKEN`
  (user token de [central.sonatype.com](https://central.sonatype.com)),
  `MAVEN_GPG_PRIVATE_KEY`, `MAVEN_GPG_PASSPHRASE`.
- Namespace `br.gov.go.saude` verificado no Sonatype Central.

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

## Nota para mantenedores: chave GPG de release

A chave GPG de assinatura de releases (`566A199A481E3355`) expira em 2028-08-30.
Antes dessa data, um mantenedor deve renovar a validade via
`gpg --edit-key 566A199A481E3355 → expire` e reenviar ao keyserver.
