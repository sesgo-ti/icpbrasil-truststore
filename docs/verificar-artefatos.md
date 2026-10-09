# Quero conferir a autenticidade dos artefatos

## Executável do serviço (GitHub Release)

Cada [GitHub Release](https://github.com/sesgo-ti/icpbrasil-truststore/releases) traz o executável
REST, o SBOM CycloneDX (`*-sbom.cdx.json`) e o `SHA256SUMS`. Depois de baixar, confira:

```bash
sha256sum -c SHA256SUMS --ignore-missing
```

Os assets da Release não têm assinatura GPG própria: a integridade vem do `SHA256SUMS`.

## Biblioteca (Maven Central)

Os artefatos no Maven Central são assinados com GPG. O Maven não verifica as assinaturas por
padrão. Para exigir essa verificação, use o
[`pgpverify-maven-plugin`](https://www.simplify4u.org/pgpverify-maven-plugin/) e inclua a chave de
release no `keysMap`:

```
8EF6 6D44 5A97 6C0A 2C3B 4FB5 566A 199A 481E 3355
```

Detalhes da chave (publicação, renovação, revogação): [MAINTAINERS.md](../MAINTAINERS.md#chave-gpg-de-release).

## Build reproduzível

O build é reproduzível: o workflow de release grava nos JARs a data do commit da tag, e o wrapper
do Maven confere o SHA-256 da sua própria distribuição. Para reconstruir a partir da tag com a
mesma data (use o mesmo JDK, Temurin 21):

```bash
git checkout vX.Y.Z
```

```bash
./mvnw clean package -DskipTests -Dproject.build.outputTimestamp="$(TZ=UTC0 git log -1 --format=%cd --date=format-local:%Y-%m-%dT%H:%M:%SZ)"
```
