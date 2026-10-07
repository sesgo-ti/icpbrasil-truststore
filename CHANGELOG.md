# Changelog

Todas as mudanças notáveis deste projeto serão documentadas neste arquivo.

O formato segue o [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/)
e o projeto adere ao [Versionamento Semântico](https://semver.org/lang/pt-BR/).

## [Unreleased]

### Adicionado

- `Cache.getCertificatesBySki` e `Cache.currentCertificates`: todos os certificados do acervo, inclusive os que compartilham SKI (#20).
- Cache de revogação: downloads concorrentes da mesma CRL ou da mesma resposta OCSP são compartilhados (#13).
- SBOM CycloneDX (`-Psbom`) e análise de dependências com osv-scanner no CI; exceções temporárias, com responsável e validade, em `osv-scanner.toml` (#17).
- GitHub Release com o executável REST, o SBOM e `SHA256SUMS`; notas extraídas do CHANGELOG, com falha se a seção da versão não existir (#14).
- `META-INF/LICENSE` nos JARs binário e de sources de `core` e `autoconfigure` (#22).
- Build reproduzível: `project.build.outputTimestamp` fixa as datas gravadas nos JARs, e o workflow de release usa a data do commit da tag; checksum da distribuição do Maven no wrapper (#15).

### Alterado

- **Incompatível:** a biblioteca deixa de registrar o BouncyCastle na JVM (`Security.addProvider`); a verificação OCSP usa uma instância própria do provider. Aplicações que dependiam desse registro precisam fazê-lo por conta própria.
- **Incompatível:** `icpbrasil-truststore.revocation.ocsp-cache-max-size` e `crl-cache-max-size` (entradas) foram substituídas por `ocsp-cache-max-bytes` (padrão 16 MiB) e `crl-cache-max-bytes` (padrão 256 MiB), com eviction por peso (#13).
- **Incompatível:** `TrustStoreRepository` persiste por geração: `recuperarGeracao()` e `armazenarGeracao(zip, hash, confirmacao)` substituem `armazenarZip`/`armazenarHash`; filesystem e S3 gravam em `geracoes/<hash>/` e trocam o ponteiro `hash.txt` por último. O layout da 0.0.1 é lido e migrado sem novo download (#16).
- `/certificate`: parâmetros validados antes da consulta (precedência 400 → 503 → 404); `ski` aceita octetos hexadecimais em maiúsculas ou minúsculas, de 1 a 64; `ski` ou `type` ausentes, vazios ou repetidos respondem 400 (#19).
- Workflow de release em jobs separados: verificação sem secrets e publicação no environment protegido `release`; actions fixadas por SHA; recuperação da GitHub Release sem republicar no Central (#21, #14).
- Spring Boot 3.5.16, BouncyCastle 1.86, AWS SDK 2.55.8, commons-codec 1.22.1 e commons-compress 1.28.0 (#17).
- Manuais: procedimento suportado de gestão das âncoras TLS e de disponibilização do serviço; o rascunho do HubSaúde foi removido (#12).

### Corrigido

- Âncoras TLS do download do ITI com o mesmo CN (reemissões e cross-signs) deixaram de se sobrescrever: o alias passou a ser o fingerprint SHA-256; certificado sem CN deixou de impedir a carga (#18).
- Montagem de cadeia: a primeira URL AIA sem o emissor correto não encerra mais a busca; entre candidatos com o mesmo SKI, o emissor é escolhido pelo nome e pela assinatura, preferindo o autoassinado, em qualquer ordem (#20).
- Acervo: a raiz autoassinada e sua versão cross-signed com o mesmo SKI são mantidas; o material PKIX usa ambas (#20).
- Lombok deixou de ser empacotado no executável REST (escopo `provided`, excluído do repackage) (#17).

### Removido

- Manual e script de certificado do HashiCorp Vault, integração que a biblioteca não possui (#12).

### Segurança

- Versões corrigidas de Tomcat (10.1.60), Netty (4.1.137), Jackson (2.21.7), Log4j API (2.25.5), HttpClient5 (5.6.3), HttpCore5 (5.4.3) e commons-lang3 (3.18.0) sobre o BOM do Spring Boot (#17).
- Exceções temporárias em `osv-scanner.toml` para GHSA-j9f9-w8pj-32f8 e GHSA-pc63-qcmh-9cmg, do Spring MVC 6.2.19, sem correção na linha 6.2: o serviço REST não usa Server-Sent Events com fragments nem `XsltView`.

## [0.0.1] - 2026-09-10

### Adicionado

- Arquitetura hexagonal em três módulos: `core` (Java puro), `autoconfigure` (wiring Spring Boot) e `rest` (microserviço standalone com fat jar).
- Download do acervo de ACs vigentes da ICP-Brasil (bundle ZIP oficial do ITI) com verificação de integridade por hash SHA-512; URLs oficiais em `IcpBrasilEndpoints`, usadas como default de `certificate-url` e `hash-url`.
- Cache em memória indexado por SKI (Subject Key Identifier), com TTL configurável e limiares de criticidade.
- Sincronização automática do acervo em background.
- Montagem de cadeia de certificados via AIA CA Issuers (suporte a DER, PEM e PKCS#7).
- Verificação de revogação via OCSP e CRL, com cache e fallback automático; `RevocationStatus.isConclusive()` distingue veredicto (`Good`/`Revoked`) de status inconclusivo.
- `PkixCertificateValidator`: validação PKIX (RFC 5280) pelo `CertPathBuilder`/`CertPathValidator` do JDK, ancorada nas raízes do acervo, com revogação de cada certificado do caminho verificada pela biblioteca e reavaliada pelo `PKIXRevocationChecker`; resultado `ValidationResult` (sealed).
- `RevocationService.lookup`, `OcspClient.lookup` e `CrlClient.lookup`: devolvem a evidência (`RevocationEvidence`) junto do `RevocationStatus`.
- `TrustMaterial`/`TrustMaterialSource`: âncoras e intermediárias derivadas do acervo em memória, memoizadas por geração (`Cache.currentIndex`).
- Dois backends de armazenamento: filesystem local e S3-compatível (AWS S3, MinIO etc.).
- Auto-configuração Spring Boot, endpoint REST opcional de consulta por SKI e health indicator.
- Metadata de configuração (`spring-configuration-metadata.json`) com default e descrição de todas as propriedades `icpbrasil-truststore.*`, para autocompletar na IDE.
- `SSLContext` e `X509TrustManager` dedicados com trust exclusivo nas ACs da ICP-Brasil.
- Proteção contra SSRF e limites de tamanho para downloads derivados de extensões de certificados (AIA, OCSP, CRL).

### Corrigido

- Downloads de AIA/OCSP/CRL: limite de tamanho aplicado durante o recebimento, redirects rejeitados, bloqueio de IPv6 ULA/CGNAT e falha de DNS tratada como bloqueio.
- OCSP: resposta aceita somente se o `CertID` corresponder ao certificado consultado, dentro da janela `thisUpdate`/`nextUpdate` e assinada pelo emissor ou por delegado válido com EKU `id-kp-OCSPSigning`.
- CRL: exige emissor, assinatura, `nextUpdate` vigente e cobertura comprovada; delta CRL, IDP não coberto, motivos parciais e extensões críticas desconhecidas são inconclusivos, nunca `Good`.
- Acervo: o cache só é publicado após validar hash e conteúdo da geração; a validade expira pelo relógio nas leituras e não é renovada por confirmações de outra geração; limites no ZIP e no download do ITI.
- Auto-configuração funciona sem AWS SDK e sem Actuator (integrações opcionais isoladas) e com a configuração mínima documentada (defaults na biblioteca); `S3Client` do consumidor é respeitado.
- Health indicator lê apenas o estado em memória; readiness do serviço standalone inclui `trustStoreCache`; `/certificate` decide 503/404 em uma única leitura e responde com `Cache-Control: no-store`.
- Publicação: `central-publishing-maven-plugin` 0.11.0 com REST excluído, SCM herdado sem sufixo de módulo e validação da tag contra a versão dos POMs.
- Mensagem de validação de `cache-ttl-max-hours` cita a faixa correta (72–720); o SKI informado ao endpoint `/certificate` é saneado antes de ir ao log.

### Alterado

- AIA, OCSP e CRL compartilham um único `CertificateHttpTransport` (bean sobrescrevível); os construtores de produção de `OcspClient`, `CrlClient` e `CertificateChainResolver` recebem o transporte em vez da `DownloadPolicy`.
- O cache de CRLs guarda a lista já decodificada (`X509CRL`) e as regras de cobertura são avaliadas sobre ela; uma CRL direta com entrada `certificateIssuer` é descartada por inteiro.
- `TrustStoreCacheHealthIndicator` recebe apenas `TrustStoreConfig` e `Cache`; `IcpBrasilCertificateProvider.validateZipIntegrity` passa a retornar `void`.
- `application.yaml` do serviço REST deixa de repetir as URLs do ITI, que vêm dos defaults da biblioteca.

### Removido

- `DownloadPolicy.validateOcspResponseSize`, `validateCrlResponseSize` e `validateAiaResponseSize`: o limite é aplicado pelo transporte durante o recebimento.
- Métodos públicos de mutação do acervo em `TrustStoreService` (`assegurarDisponibilidade`, `reposicaoArtefatosRepositorioLocal`, `carregarArtefatosNoRepositorioLocal`, `verificarDisponibilidadeRepositorioLocal`, `verificarSincronizacaoRepositorioLocal`, `assegurrarNaoExpiracaoCache`) e o enum `DisponibilidadeRepositorio`; `refresh()` é o único ponto de entrada.

[Unreleased]: https://github.com/sesgo-ti/icpbrasil-truststore/compare/9f6a0b852e7d10ecef4799396e8c250ea47cfa46...main
[0.0.1]: https://github.com/sesgo-ti/icpbrasil-truststore/tree/9f6a0b852e7d10ecef4799396e8c250ea47cfa46
