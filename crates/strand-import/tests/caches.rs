use std::collections::BTreeSet;
use std::fs;

fn seeds(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| s.to_string()).collect()
}

fn has_edge(edges: &[(String, String, Option<f32>, strand_core::EdgeKind)], src: &str, dst: &str) -> bool {
    edges.iter().any(|(s, d, ..)| s == src && d == dst)
}

#[test]
fn pub_cache_transitive() {
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path();
    // http-1.2.3 depends on collection + http_parser; collection
    // depends on flutter? no - keep it simple: collection -> chars.
    let http = cache.join("hosted/pub.dev/http-1.2.3/pubspec.yaml");
    fs::create_dir_all(http.parent().unwrap()).unwrap();
    fs::write(
        &http,
        "name: http\nversion: 1.2.3\ndependencies:\n  collection: ^1.0.0\n  http_parser: ^4.0.0\n",
    )
    .unwrap();
    let coll = cache.join("hosted/pub.dev/collection-1.19.0/pubspec.yaml");
    fs::create_dir_all(coll.parent().unwrap()).unwrap();
    fs::write(
        &coll,
        "name: collection\nversion: 1.19.0\ndependencies:\n  chars: ^1.2.0\n",
    )
    .unwrap();
    let parser = cache.join("hosted/pub.dev/http_parser-4.1.0/pubspec.yaml");
    fs::create_dir_all(parser.parent().unwrap()).unwrap();
    fs::write(&parser, "name: http_parser\nversion: 4.1.0\n").unwrap();
    let chars = cache.join("hosted/pub.dev/chars-1.4.0/pubspec.yaml");
    fs::create_dir_all(chars.parent().unwrap()).unwrap();
    fs::write(&chars, "name: chars\nversion: 1.4.0\n").unwrap();

    let edges = strand_import::caches::pub_cache_edges(
        &seeds(&["http@1.2.3", "collection@1.19.0", "http_parser@4.1.0", "chars@1.4.0"]),
        cache,
    );
    assert!(has_edge(&edges, "http@1.2.3", "collection@1.19.0"), "{edges:?}");
    assert!(has_edge(&edges, "http@1.2.3", "http_parser@4.1.0"));
    assert!(has_edge(&edges, "collection@1.19.0", "chars@1.4.0"));
}

#[test]
fn go_cache_transitive() {
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path();
    // github.com/a/mod@v1.0.0 requires github.com/b/dep v0.2.0;
    // dep requires nothing else.
    let m1 = cache.join("github.com/a/mod@v1.0.0/go.mod");
    fs::create_dir_all(m1.parent().unwrap()).unwrap();
    fs::write(
        &m1,
        "module github.com/a/mod\n\ngo 1.21\n\nrequire (\n\tgithub.com/b/dep v0.2.0\n\tgithub.com/c/leaf v1.0.0 // indirect\n)\n",
    )
    .unwrap();
    let m2 = cache.join("github.com/b/dep@v0.2.0/go.mod");
    fs::create_dir_all(m2.parent().unwrap()).unwrap();
    fs::write(&m2, "module github.com/b/dep\n\ngo 1.21\n").unwrap();
    let m3 = cache.join("github.com/c/leaf@v1.0.0/go.mod");
    fs::create_dir_all(m3.parent().unwrap()).unwrap();
    fs::write(&m3, "module github.com/c/leaf\n\ngo 1.21\n").unwrap();

    let edges = strand_import::caches::go_cache_edges(
        &seeds(&[
            "github.com/a/mod v1.0.0",
            "github.com/b/dep v0.2.0",
            "github.com/c/leaf v1.0.0",
        ]),
        cache,
    );
    assert!(has_edge(&edges, "github.com/a/mod v1.0.0", "github.com/b/dep v0.2.0"), "{edges:?}");
    assert!(has_edge(&edges, "github.com/a/mod v1.0.0", "github.com/c/leaf v1.0.0"));
}

#[test]
fn go_cache_escaped_uppercase() {
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path();
    // Module cache escapes uppercase: github.com/BurntSushi/toml
    // lives at github.com/!burnt!sushi/toml@v1.0.0.
    let m = cache.join("github.com/!burnt!sushi/toml@v1.0.0/go.mod");
    fs::create_dir_all(m.parent().unwrap()).unwrap();
    fs::write(&m, "module github.com/BurntSushi/toml\n\ngo 1.21\n").unwrap();
    let edges = strand_import::caches::go_cache_edges(
        &seeds(&["github.com/BurntSushi/toml v1.0.0"]),
        cache,
    );
    // No deps inside; only self-loop node declaration expected.
    assert!(edges.iter().any(|(s, d, ..)| s == d && s == "github.com/BurntSushi/toml v1.0.0"), "{edges:?}");
}

#[test]
fn nuget_cache_nuspec_deps() {
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path();
    let nuspec = cache.join("newtonsoft.json/13.0.1/newtonsoft.json.13.0.1.nuspec");
    fs::create_dir_all(nuspec.parent().unwrap()).unwrap();
    fs::write(
        &nuspec,
        r#"<?xml version="1.0"?>
<package><metadata><dependencies>
  <group targetFramework=".NETStandard2.0">
    <dependency id="Microsoft.CSharp" version="4.7.0" />
    <dependency id="System.Runtime.CompilerServices.Unsafe" version="[4.5.3, )" />
  </group>
</dependencies></metadata></package>"#,
    )
    .unwrap();
    // Second-level package with a versionless dep resolved via lock.
    let nuspec2 = cache
        .join("microsoft.csharp/4.7.0/microsoft.csharp.4.7.0.nuspec");
    fs::create_dir_all(nuspec2.parent().unwrap()).unwrap();
    fs::write(
        &nuspec2,
        r#"<package><metadata><dependencies>
  <dependency id="System.ValueTuple" version="4.5.0" />
</dependencies></metadata></package>"#,
    )
    .unwrap();
    let nuspec3 = cache
        .join("system.valuetuple/4.5.0/system.valuetuple.4.5.0.nuspec");
    fs::create_dir_all(nuspec3.parent().unwrap()).unwrap();
    fs::write(&nuspec3, "<package><metadata/></package>").unwrap();

    let edges = strand_import::caches::nuget_cache_edges(
        &seeds(&["Newtonsoft.Json@13.0.1", "Microsoft.CSharp@4.7.0", "System.ValueTuple@4.5.0"]),
        cache,
    );
    assert!(has_edge(&edges, "Newtonsoft.Json@13.0.1", "Microsoft.CSharp@4.7.0"), "{edges:?}");
    // Range version `[4.5.3, )` is not a pin -> resolves via lock
    // if present else bare. System.Runtime.CompilerServices.Unsafe
    // is not in seed, so bare name edge expected.
    assert!(has_edge(&edges, "Newtonsoft.Json@13.0.1", "System.Runtime.CompilerServices.Unsafe"));
    assert!(has_edge(&edges, "Microsoft.CSharp@4.7.0", "System.ValueTuple@4.5.0"));
}

#[test]
fn maven_cache_pom_transitive() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    let pom = repo
        .join("com/google/guava/guava/31.1-jre/guava-31.1-jre.pom");
    fs::create_dir_all(pom.parent().unwrap()).unwrap();
    fs::write(
        &pom,
        r#"<project><modelVersion>4.0.0</modelVersion>
<groupId>com.google.guava</groupId><artifactId>guava</artifactId><version>31.1-jre</version>
<dependencies>
  <dependency><groupId>com.google.guava</groupId><artifactId>failureaccess</artifactId><version>1.0.1</version></dependency>
  <dependency><groupId>org.checkerframework</groupId><artifactId>checker-qual</artifactId></dependency>
</dependencies></project>"#,
    )
    .unwrap();
    let pom2 = repo
        .join("com/google/guava/failureaccess/1.0.1/failureaccess-1.0.1.pom");
    fs::create_dir_all(pom2.parent().unwrap()).unwrap();
    fs::write(&pom2, "<project/>").unwrap();

    let edges = strand_import::caches::maven_cache_edges(
        &seeds(&["com.google.guava:guava@31.1-jre", "com.google.guava:failureaccess@1.0.1"]),
        repo,
    );
    assert!(
        has_edge(&edges, "com.google.guava:guava@31.1-jre", "com.google.guava:failureaccess@1.0.1"),
        "{edges:?}"
    );
    // Versionless checker-qual resolves to bare (not in lock).
    assert!(has_edge(&edges, "com.google.guava:guava@31.1-jre", "org.checkerframework:checker-qual"));
}

#[test]
fn mix_deps_project_local() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    // deps/phoenix/mix.exs declares plug + telemetry; plug declares
    // mime + plug_crypto (transitive through deps/plug).
    for (pkg, deps) in [
        ("phoenix", "  {:plug, \"~> 1.14\"},\n  {:telemetry, \"~> 1.0\"},"),
        ("plug", "  {:mime, \"~> 2.0\"},\n  {:plug_crypto, \"~> 1.2\"},"),
        ("telemetry", ""),
        ("mime", ""),
        ("plug_crypto", ""),
    ] {
        let p = root.join(format!("deps/{pkg}/mix.exs"));
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(
            &p,
            format!("defmodule {pkg} do\n  def deps do\n    [\n{deps}\n    ]\n  end\nend\n"),
        )
        .unwrap();
    }
    let edges = strand_import::caches::mix_deps_edges(
        &seeds(&[
            "phoenix@1.7.0",
            "plug@1.14.0",
            "telemetry@1.2.0",
            "mime@2.0.0",
            "plug_crypto@1.2.0",
        ]),
        root,
    );
    assert!(has_edge(&edges, "phoenix@1.7.0", "plug@1.14.0"), "{edges:?}");
    assert!(has_edge(&edges, "phoenix@1.7.0", "telemetry@1.2.0"));
    assert!(has_edge(&edges, "plug@1.14.0", "mime@2.0.0"));
    assert!(has_edge(&edges, "plug@1.14.0", "plug_crypto@1.2.0"));
}

#[test]
fn swift_checkouts_package_swift() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    // .build/checkouts/Alamofire-deadbeef/Package.swift depends on
    // a second package; pins are identity@version.
    let co = root.join(".build/checkouts/Alamofire-deadbeef");
    fs::create_dir_all(&co).unwrap();
    fs::write(
        co.join("Package.swift"),
        "// swift-tools-version:5.7\nimport PackageDescription\nlet package = Package(name: \"Alamofire\", dependencies: [.package(url: \"https://github.com/Alamofire/AlamofireImage.git\", from: \"4.0.0\")])\n",
    )
    .unwrap();
    let co2 = root.join(".build/checkouts/AlamofireImage-cafebabe");
    fs::create_dir_all(&co2).unwrap();
    fs::write(co2.join("Package.swift"), "let package = Package(name: \"x\")\n").unwrap();

    let edges = strand_import::caches::swift_checkout_edges(
        &seeds(&["alamofire@5.8.0", "alamofireimage@4.1.0"]),
        root,
    );
    assert!(has_edge(&edges, "alamofire@5.8.0", "alamofireimage@4.1.0"), "{edges:?}");
}

#[test]
fn carthage_checkouts_cartfile() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    // SourcePackages/checkouts/Repo-deadbeef/Cartfile pins a dep.
    let co = root.join("SourcePackages/checkouts/Repo-deadbeef");
    fs::create_dir_all(&co).unwrap();
    fs::write(
        co.join("Cartfile"),
        "github \"Alamofire/Alamofire\" \"5.8.0\"\n",
    )
    .unwrap();
    let co2 = root.join("SourcePackages/checkouts/Alamofire-cafebabe");
    fs::create_dir_all(&co2).unwrap();
    fs::write(co2.join("Cartfile"), "# none\n").unwrap();

    let edges = strand_import::caches::carthage_checkout_edges(
        &seeds(&["myorg/repo@1.0.0", "alamofire/alamofire@5.8.0"]),
        root,
    );
    assert!(has_edge(&edges, "myorg/repo@1.0.0", "alamofire/alamofire@5.8.0"), "{edges:?}");
}

#[test]
fn empty_cache_returns_empty() {
    let dir = tempfile::tempdir().unwrap();
    let s = seeds(&["a@1.0.0"]);
    assert!(strand_import::caches::pub_cache_edges(&s, dir.path()).is_empty()
        || strand_import::caches::pub_cache_edges(&s, dir.path())
            .iter()
            .all(|(a, b, ..)| a == b));
    assert!(strand_import::caches::go_cache_edges(&s, dir.path()).is_empty()
        || strand_import::caches::go_cache_edges(&s, dir.path())
            .iter()
            .all(|(a, b, ..)| a == b));
}

#[test]
fn pip_site_packages_dist_info() {
    let dir = tempfile::tempdir().unwrap();
    let sp = dir
        .path()
        .join(".venv/lib/python3.11/site-packages");
    let di = sp.join("requests-2.31.0.dist-info");
    fs::create_dir_all(&di).unwrap();
    fs::write(
        di.join("METADATA"),
        "Metadata-Version: 2.1\nName: requests\nVersion: 2.31.0\n\
         Requires-Dist: charset_normalizer (<4,>=2)\n\
         Requires-Dist: idna (<4,>=2.5)\n\
         Requires-Dist: urllib3 (<3,>=1.21.1)\n\
         Requires-Dist: certifi (>=2017.4.17)\n",
    )
    .unwrap();
    let s = seeds(&[
        "requests@2.31.0",
        "urllib3@2.0.7",
        "idna@3.6",
        "certifi@2024.2.2",
        "charset-normalizer@3.3.2",
    ]);
    let edges = strand_import::caches::pip_site_packages_edges(&s, dir.path());
    assert!(has_edge(&edges, "requests@2.31.0", "urllib3@2.0.7"), "{edges:?}");
    assert!(has_edge(&edges, "requests@2.31.0", "idna@3.6"), "{edges:?}");
    assert!(has_edge(&edges, "requests@2.31.0", "certifi@2024.2.2"), "{edges:?}");
    // charset_normalizer normalizes to charset-normalizer.
    assert!(has_edge(&edges, "requests@2.31.0", "charset-normalizer@3.3.2"), "{edges:?}");
}

#[test]
fn erlang_app_applications() {
    let dir = tempfile::tempdir().unwrap();
    let ebin = dir.path().join("_build/default/lib/cowboy/ebin");
    fs::create_dir_all(&ebin).unwrap();
    fs::write(
        ebin.join("cowboy.app"),
        "{application, cowboy,\n [{description, \"Small, fast, modern HTTP server.\"},\n  {vsn, \"2.10.0\"},\n  {registered, [cowboy_clock, cowboy_sup, cowboy_stream_h]},\n  {applications, [kernel, stdlib, cowlib, ranch]},\n  {modules, []}]}.\n",
    )
    .unwrap();
    let s = seeds(&["cowboy@2.10.0", "cowlib@2.12.1", "ranch@2.1.0"]);
    let edges = strand_import::caches::erlang_app_edges(&s, dir.path());
    assert!(has_edge(&edges, "cowboy@2.10.0", "cowlib@2.12.1"), "{edges:?}");
    assert!(has_edge(&edges, "cowboy@2.10.0", "ranch@2.1.0"), "{edges:?}");
    // kernel/stdlib are OTP apps, filtered out.
    assert!(!edges.iter().any(|(_, d, ..)| d == "kernel" || d == "stdlib"), "{edges:?}");
}

#[test]
fn renv_library_description() {
    let dir = tempfile::tempdir().unwrap();
    let desc = dir.path().join("renv/library/4.3.0/ggplot2");
    fs::create_dir_all(&desc).unwrap();
    fs::write(
        desc.join("DESCRIPTION"),
        "Package: ggplot2\nVersion: 3.5.0\nDepends: R (>= 3.3), scales (>= 1.2.0), gtable\nImports: grDevices, graphics, methods, stats, utils, lifecycle, rlang, glue\n",
    )
    .unwrap();
    let s = seeds(&[
        "ggplot2@3.5.0",
        "scales@1.3.0",
        "gtable@0.3.4",
        "rlang@1.1.0",
    ]);
    let edges = strand_import::caches::renv_library_edges(&s, dir.path());
    assert!(has_edge(&edges, "ggplot2@3.5.0", "scales@1.3.0"), "{edges:?}");
    assert!(has_edge(&edges, "ggplot2@3.5.0", "gtable@0.3.4"), "{edges:?}");
    assert!(has_edge(&edges, "ggplot2@3.5.0", "rlang@1.1.0"), "{edges:?}");
}

#[test]
fn stack_pkgdb_conf_depends() {
    let home = tempfile::tempdir().unwrap();
    let proj = tempfile::tempdir().unwrap();
    let pkgdb = home.path().join("snapshots/x86_64-linux/ghc-9.6.3/pkgdb");
    fs::create_dir_all(&pkgdb).unwrap();
    fs::write(
        pkgdb.join("aeson-2.1.0.0-0123abcd.conf"),
        "name: aeson\nversion: 2.1.0.0\ndepends: base-4.17.2.0-aaaabbbb,\n  text-2.0.2-ccccdddd,\n  vector-0.13.1.0-eeeeffff\n",
    )
    .unwrap();
    fs::write(
        pkgdb.join("base-4.17.2.0-aaaabbbb.conf"),
        "name: base\nversion: 4.17.2.0\ndepends:\n",
    )
    .unwrap();
    fs::write(
        pkgdb.join("text-2.0.2-ccccdddd.conf"),
        "name: text\nversion: 2.0.2\ndepends: base-4.17.2.0-aaaabbbb\n",
    )
    .unwrap();
    fs::write(
        pkgdb.join("vector-0.13.1.0-eeeeffff.conf"),
        "name: vector\nversion: 0.13.1.0\ndepends:\n",
    )
    .unwrap();
    let s = seeds(&[
        "aeson@2.1.0.0",
        "base@4.17.2.0",
        "text@2.0.2",
        "vector@0.13.1.0",
    ]);
    let edges = strand_import::caches::stack_pkgdb_edges(&s, home.path(), proj.path());
    assert!(has_edge(&edges, "aeson@2.1.0.0", "base@4.17.2.0"), "{edges:?}");
    assert!(has_edge(&edges, "aeson@2.1.0.0", "text@2.0.2"), "{edges:?}");
    assert!(has_edge(&edges, "aeson@2.1.0.0", "vector@0.13.1.0"), "{edges:?}");
    // Transitive: text -> base.
    assert!(has_edge(&edges, "text@2.0.2", "base@4.17.2.0"), "{edges:?}");
}
