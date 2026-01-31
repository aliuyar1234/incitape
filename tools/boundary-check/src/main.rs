use cargo_metadata::{MetadataCommand, Package};
use std::collections::{BTreeMap, BTreeSet};

fn main() {
    let metadata = match MetadataCommand::new().exec() {
        Ok(metadata) => metadata,
        Err(err) => {
            eprintln!("boundary-check: failed to read cargo metadata: {err}");
            std::process::exit(2);
        }
    };

    let workspace: BTreeSet<_> = metadata.workspace_members.iter().cloned().collect();

    let mut packages = BTreeMap::new();
    for pkg in metadata.packages {
        if workspace.contains(&pkg.id) {
            packages.insert(pkg.name.clone(), pkg);
        }
    }

    let allowlist = allowlist();
    let mut violations = Vec::new();

    for (name, pkg) in &packages {
        if name == "boundary-check" {
            continue;
        }
        let allowed = match allowlist.get(name.as_str()) {
            Some(allowed) => allowed,
            None => continue,
        };

        let deps = workspace_deps(pkg, &packages);
        for dep in deps {
            if dep == *name {
                continue;
            }
            if !allowed.contains(dep.as_str()) {
                violations.push(format!("{name} -> {dep}"));
            }
        }
    }

    if violations.is_empty() {
        println!("boundary-check: ok");
    } else {
        eprintln!("boundary-check: forbidden workspace dependencies detected:");
        for item in violations {
            eprintln!("  {item}");
        }
        std::process::exit(1);
    }
}

fn workspace_deps<'a>(pkg: &'a Package, workspace: &'a BTreeMap<String, Package>) -> Vec<String> {
    let mut deps = Vec::new();
    for dep in &pkg.dependencies {
        if workspace.contains_key(&dep.name) {
            deps.push(dep.name.clone());
        }
    }
    deps
}

fn allowlist() -> BTreeMap<&'static str, BTreeSet<&'static str>> {
    let mut map = BTreeMap::new();
    map.insert("incitape-core", BTreeSet::new());
    map.insert("incitape-tape", set(["incitape-core"]));
    map.insert("incitape-redaction", set(["incitape-core"]));
    map.insert(
        "incitape-recorder",
        set(["incitape-core", "incitape-tape", "incitape-redaction"]),
    );
    map.insert("incitape-replay", set(["incitape-core", "incitape-tape"]));
    map.insert("incitape-analyzer", set(["incitape-core", "incitape-tape"]));
    map.insert(
        "incitape-minimize",
        set(["incitape-core", "incitape-tape", "incitape-analyzer"]),
    );
    map.insert(
        "incitape-eval",
        set([
            "incitape-core",
            "incitape-tape",
            "incitape-analyzer",
            "incitape-redaction",
        ]),
    );
    map.insert(
        "incitape-report",
        set(["incitape-core", "incitape-tape", "incitape-analyzer"]),
    );
    map.insert(
        "incitape-cli",
        set([
            "incitape-core",
            "incitape-tape",
            "incitape-redaction",
            "incitape-recorder",
            "incitape-replay",
            "incitape-analyzer",
            "incitape-minimize",
            "incitape-eval",
            "incitape-report",
        ]),
    );
    map
}

fn set<const N: usize>(items: [&'static str; N]) -> BTreeSet<&'static str> {
    items.into_iter().collect()
}
