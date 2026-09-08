#!/usr/bin/env python3
"""Inspecao local sem publicador, assinatura, credenciais ou acesso a rede."""

import hashlib
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET
from zipfile import ZipFile, ZIP_DEFLATED


def main():
    ns = {"m": "http://maven.apache.org/POM/4.0.0"}
    root = Path(__file__).resolve().parent.parent
    effective = ET.parse(root / "target/release-effective-pom.xml").getroot()
    projects = effective.findall("m:project", ns)
    parent = "icpbrasil-truststore"
    libraries = [parent + "-core", parent + "-autoconfigure"]
    expected = [parent, *libraries, parent + "-rest"]

    def text(element, path):
        return element.findtext(path, default="", namespaces=ns)

    def require(condition, message):
        if not condition:
            raise ValueError(message)

    require([text(p, "m:artifactId") for p in projects] == expected,
            "Reactor efetivo deve conter parent, core, autoconfigure e REST, nesta ordem")
    version = text(projects[0], "m:version")
    require(re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", version),
            "Versao Maven deve ser estavel, sem SNAPSHOT ou sufixo")
    tag = sys.argv[1] if len(sys.argv) > 1 else ""
    require(not tag or tag == "v" + version, "Tag diverge da versao Maven")
    scm = "https://github.com/sesgo-ti/icpbrasil-truststore"
    for project in projects:
        artifact = text(project, "m:artifactId")
        require(text(project, "m:groupId") == "br.gov.go.saude", f"groupId incorreto: {artifact}")
        require(text(project, "m:version") == version, f"Versao divergente: {artifact}")
        if artifact != parent:
            require(text(project, "m:parent/m:version") == version, f"Parent divergente: {artifact}")
        for element in project.iter():
            if element.tag == "{" + ns["m"] + "}version":
                require("SNAPSHOT" not in (element.text or "").upper(), f"SNAPSHOT: {artifact}")
        require(text(project, "m:url") == scm, f"URL herdada incorreta: {artifact}")
        for field, value in {
            "url": scm,
            "connection": "scm:git:" + scm + ".git",
            "developerConnection": "scm:git:git@github.com:sesgo-ti/icpbrasil-truststore.git",
            "tag": "v" + version,
        }.items():
            require(text(project, "m:scm/m:" + field) == value, f"SCM {field} incorreto: {artifact}")
        publisher = project.find(
            "m:build/m:plugins/m:plugin[m:artifactId='central-publishing-maven-plugin']", ns)
        require(publisher is not None, f"Publicador ausente: {artifact}")
        require(text(publisher, "m:version") == "0.11.0", f"Reavaliar semantica do publicador: {artifact}")
        excluded = publisher.findall("m:configuration/m:excludeArtifacts/*", ns)
        require([item.text for item in excluded] == [parent + "-rest"],
                f"Exclusao defensiva do REST incorreta: {artifact}")

    # Allowlist explicita: nunca copiar target/ inteiro nem staging do publicador.
    files = {}
    for artifact in [parent, *libraries]:
        directory = root if artifact == parent else root / artifact
        base = f"br/gov/go/saude/{artifact}/{version}/{artifact}-{version}"
        files[base + ".pom"] = (directory / "pom.xml").read_bytes()
        if artifact == parent:
            continue
        for classifier in ["", "-sources", "-javadoc"]:
            jar = directory / "target" / f"{artifact}-{version}{classifier}.jar"
            with ZipFile(jar) as archive:
                names = archive.namelist()
                suffix = {"": ".class", "-sources": ".java", "-javadoc": ".html"}[classifier]
                require(any(name.endswith(suffix) for name in names), f"JAR vazio/invalido: {jar}")
                require(not any(name.startswith("BOOT-INF/") for name in names), f"Fat JAR: {jar}")
                if classifier in ("", "-sources"):
                    require(archive.read("META-INF/LICENSE") == (root / "LICENSE").read_bytes(),
                            f"Licenca ausente/divergente: {jar}")
            files[base + classifier + ".jar"] = jar.read_bytes()

    bundle = root / "target/release-inspection/unsigned-bundle.zip"
    bundle.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(bundle, "w", ZIP_DEFLATED) as archive:
        for name, data in sorted(files.items()):
            archive.writestr(name, data)
            for algorithm in ["md5", "sha1", "sha256", "sha512"]:
                archive.writestr(name + "." + algorithm, hashlib.new(algorithm, data).hexdigest())
    with ZipFile(bundle) as archive:
        require(archive.testzip() is None, "ZIP corrompido")
        require(len(archive.namelist()) == 45, "Composicao inesperada do bundle")
    print(f"Versoes e SCM conferidos nos 4 POMs efetivos: {version}")
    print("Bundle LOCAL NAO ASSINADO: 3 POMs + 6 JARs + 36 checksums; REST excluido")
    for name in sorted(files):
        print(name)
    print(f"Bundle: {bundle}")
    print("Nao executa nem valida o publicador Sonatype; nao substitui validacao Central/GPG.")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, ET.ParseError) as error:
        sys.exit(f"Verificacao de release falhou: {error}")
