use std::path::Path;

#[test]
fn discovers_only_the_twelve_production_programs() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let paths = mcu::program_sources(&root).unwrap();
    let mut names = paths
        .iter()
        .map(|path| path.file_stem().unwrap().to_str().unwrap())
        .collect::<Vec<_>>();
    names.sort_unstable();
    assert_eq!(
        names,
        [
            "bsort",
            "case_mark",
            "case_swap",
            "copy",
            "firewall",
            "fletcher32",
            "just_drop",
            "just_tx",
            "log2",
            "noop",
            "prime",
            "strcmp"
        ]
    );
    for path in paths {
        assert!(
            path.parent().unwrap().join("README.md").is_file(),
            "{}",
            path.display()
        );
    }
}
