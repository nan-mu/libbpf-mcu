use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, ensure};
use mcu_image::{Mode, program_name, write_if_changed};

use mcu_project::Tools;

pub struct Generate<'a> {
    pub root: &'a Path,
    pub build: &'a Path,
    pub sources: &'a [PathBuf],
    pub modes: &'a [Mode],
    pub tools: &'a Tools,
}

pub struct Execute {
    pub graph: PathBuf,
    pub root: PathBuf,
    pub ninja: PathBuf,
    pub targets: Vec<String>,
    dependencies: BTreeMap<PathBuf, Vec<PathBuf>>,
}

#[derive(Default)]
struct Graph {
    text: String,
    dependencies: BTreeMap<PathBuf, Vec<PathBuf>>,
}

impl std::fmt::Write for Graph {
    fn write_str(&mut self, text: &str) -> std::fmt::Result {
        self.text.push_str(text);
        Ok(())
    }
}

impl Graph {
    fn record(&mut self, outputs: &[&Path], inputs: &[&Path], tools: &[&Path]) {
        let dependencies: Vec<_> = inputs
            .iter()
            .chain(tools)
            .map(|path| path.to_path_buf())
            .collect();
        for output in outputs {
            self.dependencies
                .insert(output.to_path_buf(), dependencies.clone());
        }
    }
}

impl Execute {
    /// Check the same file dependencies the generator gave Ninja.
    /// Clang's dynamic SDK dependencies are checked separately from its depfiles.
    pub fn output_current(&self, output: &Path) -> bool {
        let Ok(mtime) = output.metadata().and_then(|metadata| metadata.modified()) else {
            return false;
        };
        self.dependencies.get(output).is_none_or(|inputs| {
            inputs.iter().all(|input| {
                input
                    .metadata()
                    .and_then(|metadata| metadata.modified())
                    .is_ok_and(|changed| changed <= mtime)
                    && self.output_current(input)
            })
        })
    }

    pub fn run(&self) -> Result<()> {
        let status = Command::new(&self.ninja)
            .current_dir(&self.root)
            .arg("-f")
            .arg(&self.graph)
            .args(&self.targets)
            .status()
            .context("execute Ninja")?;
        ensure!(status.success(), "Ninja failed ({status})");
        Ok(())
    }
}

fn path_text(path: &Path) -> Result<&str> {
    let text = path.to_str().context("Ninja requires UTF-8 paths")?;
    ensure!(
        !text.contains(['\r', '\n', '|']),
        "unsupported character in path {text:?}"
    );
    Ok(text)
}

fn ninja(text: &str) -> String {
    text.replace('$', "$$")
        .replace(' ', "$ ")
        .replace(':', "$:")
}

fn shell(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''")).replace('$', "$$")
}

fn paths(paths: &[&Path]) -> Result<String> {
    paths
        .iter()
        .map(|path| Ok(ninja(path_text(path)?)))
        .collect::<Result<Vec<_>>>()
        .map(|v| v.join(" "))
}

fn edge(
    out: &mut Graph,
    rule: &str,
    outputs: &[&Path],
    inputs: &[&Path],
    tools: &[&Path],
    gate: Option<&Path>,
    vars: &[(&str, String)],
) -> Result<()> {
    use std::fmt::Write;
    if rule != "phony" {
        out.record(outputs, inputs, tools);
    }
    write!(out, "build {}: {rule} {}", paths(outputs)?, paths(inputs)?)?;
    if !tools.is_empty() {
        write!(out, " | {}", paths(tools)?)?;
    }
    if let Some(gate) = gate {
        write!(out, " || {}", paths(&[gate])?)?;
    }
    writeln!(out)?;
    for (key, value) in vars {
        writeln!(out, "  {key} = {value}")?;
    }
    Ok(())
}

fn quote(path: &Path) -> Result<String> {
    Ok(shell(path_text(path)?))
}
fn arg(key: &'static str, path: &Path) -> Result<(&'static str, String)> {
    Ok((key, quote(path)?))
}

const RULES: &str = r#"
# The tool writes a persistent depfile. Ninja reads it on subsequent builds.
rule compile_bpf
  command = $clang -O2 --target=bpf -Wall -Wno-missing-declarations -fno-stack-protector -g $prefix -fdebug-compilation-dir=. -nostdinc -I include-bpf -include vmlinux.h -MD -MF $dependencies -MQ $out -c $in -o $out
  depfile = $depfile_path
  description = BPF COMPILE $out
rule verify_bpf
  command = $object bpf-verify --checker $prevail --input $in --output $out --dependencies $dependencies --source $source --sdk include-bpf
  description = BPF VERIFY $out
rule source
  command = cp $in $out
  description = COPY SOURCE $out
rule compile_rv32
  command = $clang -O2 --target=riscv32-unknown-none-elf -march=rv32imc -mabi=ilp32 -nostdlib -ffreestanding -fno-builtin -fno-exceptions -fno-rtti -fno-jump-tables -fno-omit-frame-pointer -Wall -Wno-unused-function -g $prefix -fdebug-compilation-dir=. -nostdinc -I include -include vmlinux.h -mno-relax -MD -MF $dependencies -MQ $out -c $in -o $out
  depfile = $depfile_path
  description = RV32 COMPILE $out
rule check_native
  command = $object check-native --input $in --output $out --dependencies $dependencies --source $source --sdk include
  description = RV32 DEPENDENCIES $out
rule link_aot
  command = $lld -m elf32lriscv --no-relax --emit-relocs -T $linker $in -o $out
  description = AOT LINK $out
rule image_aot
  command = $object image-aot --input $bpf --reference $rv32 --elf $linked --output-dir $images --program $name
  description = AOT IMAGE $out
rule image_jit
  command = $jit compile --input $in --output-dir $images
  description = JIT IMAGE $out
rule image_ebpf
  command = $object image-ebpf --input $bpf --map-layout $layout --output-dir $images
  description = RBPF IMAGE $out
rule prepare_disassembly
  command = $object report-prepare --image $image --layout $layout --output $out
  description = PREPARE DISASSEMBLY $out
rule disassemble
  command = $objdump -d -z $isa $in > $out
  description = DISASSEMBLE $out
rule recipes
  command = $ninja -f $in -t commands $recipe_targets > $out
  description = BUILD RECIPES $out
rule report
  command = $object report --program-dir $program --linked $linked --listing $listing --modes=$modes
  description = REPORT $out
rule index
  command = $object index --program-dir $program --modes=$modes
  description = INDEX $out
"#;

impl Generate<'_> {
    pub fn run(self) -> Result<Execute> {
        use std::fmt::Write;

        ensure!(!self.sources.is_empty(), "no programs selected");
        let graph = self.build.join("build.ninja");
        let mut body = Graph::default();
        writeln!(
            body,
            "# Generated by mcu. Run Ninja from the checkout root.\nninja_required_version = 1.10"
        )?;
        writeln!(body, "builddir = {}", ninja(path_text(self.build)?))?;
        writeln!(body, "{}", self.tools.graph_comment()?)?;
        for (key, path) in self.tools.inputs() {
            ensure!(path.is_absolute(), "{key} path must be absolute");
            writeln!(body, "{key} = {}", quote(path)?)?;
        }
        writeln!(
            body,
            "prefix = {}",
            shell(&format!("-ffile-prefix-map={}/=", path_text(self.root)?))
        )?;
        body.write_str(RULES)?;

        let mut targets = BTreeSet::new();
        for source in self.sources {
            let program = program_name(source)?;
            ensure!(
                targets.insert(program.to_owned()),
                "duplicate program {program}"
            );
            self.program(&mut body, &graph, source, program)?;
        }
        writeln!(
            body,
            "default {}",
            targets.iter().cloned().collect::<Vec<_>>().join(" ")
        )?;
        write_if_changed(&graph, body.text.as_bytes())?;
        Ok(Execute {
            graph,
            root: self.root.to_owned(),
            ninja: self.tools.ninja.clone(),
            targets: targets.into_iter().collect(),
            dependencies: body.dependencies,
        })
    }

    fn program(
        &self,
        graph: &mut Graph,
        graph_path: &Path,
        source: &Path,
        name: &str,
    ) -> Result<()> {
        let intermediate = self.build.join("intermediates").join(name);
        let listing = intermediate.join("report");
        let program = self.build.join(name);
        let objects = program.join("objects");
        let images = program.join("images");
        for dir in [&listing, &objects] {
            fs::create_dir_all(dir)?;
        }
        if !self.modes.is_empty() {
            fs::create_dir_all(&images)?;
        }

        let raw_bpf = intermediate.join(format!("{name}_bpf.o"));
        let bpf = objects.join(format!("{name}_bpf.o"));
        let c = program.join(format!("{name}.c"));
        let bpf_dep = intermediate.join("bpf.d");
        self.compile(graph, "compile_bpf", &raw_bpf, source, &bpf_dep, None)?;
        edge(
            graph,
            "verify_bpf",
            &[&bpf],
            &[&raw_bpf],
            &[&self.tools.prevail, &self.tools.object, &bpf_dep],
            None,
            &[arg("dependencies", &bpf_dep)?, arg("source", source)?],
        )?;
        edge(graph, "source", &[&c], &[source], &[], Some(&bpf), &[])?;

        let raw_rv32 = intermediate.join(format!("{name}_rv32.raw.o"));
        let rv32 = if self.modes.contains(&Mode::Aot) {
            &objects
        } else {
            &intermediate
        }
        .join(format!("{name}_rv32.o"));
        let linked = intermediate.join(format!("{name}_rv32.elf"));
        let linker = intermediate.join("zero.ld");
        let need_aot = self.modes.contains(&Mode::Aot) || self.modes.contains(&Mode::Ebpf);
        let mut report_inputs = vec![c.as_path(), bpf.as_path()];
        let mut index_inputs = report_inputs.clone();
        let mut upstream = vec![bpf.clone()];
        let obj = &self.tools.object;
        let aot_dir = if self.modes.contains(&Mode::Aot) {
            &images
        } else {
            &intermediate
        };
        let aot_image = aot_dir.join("llvm-aot.bin");
        let aot_layout = aot_dir.join("llvm-aot.json");

        if need_aot {
            write_if_changed(&linker, mcu_image::linker_script(0, 1 << 24, 0).as_bytes())?;
            let rv_dep = intermediate.join("rv32.d");
            self.compile(
                graph,
                "compile_rv32",
                &raw_rv32,
                source,
                &rv_dep,
                Some(&bpf),
            )?;
            edge(
                graph,
                "check_native",
                &[&rv32],
                &[&raw_rv32],
                &[obj, &rv_dep],
                Some(&bpf),
                &[arg("dependencies", &rv_dep)?, arg("source", source)?],
            )?;
            edge(
                graph,
                "link_aot",
                &[&linked],
                &[&rv32],
                &[&self.tools.lld, &linker],
                Some(&bpf),
                &[arg("linker", &linker)?],
            )?;
            edge(
                graph,
                "image_aot",
                &[&aot_image, &aot_layout],
                &[&linked, &rv32, &bpf],
                &[obj],
                None,
                &[
                    arg("linked", &linked)?,
                    arg("rv32", &rv32)?,
                    arg("bpf", &bpf)?,
                    arg("images", aot_dir)?,
                    ("name", name.to_owned()),
                ],
            )?;
        }

        let mut image_members = Vec::new();
        let mut listings = vec![listing.join("bpf.txt")];
        self.disassemble(graph, &listings[0], &bpf, "")?;
        for mode in self.modes {
            let image = images.join(format!("{mode}.bin"));
            let layout = images.join(format!("{mode}.json"));
            let text = listing.join(format!("{mode}.txt"));
            let disasm = listing.join(format!("{mode}.elf"));
            match mode {
                Mode::Aot => {
                    report_inputs.extend([rv32.as_path(), linked.as_path()]);
                    index_inputs.push(&rv32);
                    self.disassemble(graph, &text, &linked, "--mattr=+m,+c")?;
                }
                Mode::Jit => {
                    edge(
                        graph,
                        "image_jit",
                        &[&image, &layout],
                        &[&bpf],
                        &[&self.tools.jit],
                        None,
                        &[arg("images", &images)?],
                    )?;
                    self.prepare(graph, &disasm, &image, &layout)?;
                    self.disassemble(graph, &text, &disasm, "--mattr=+m,-c")?;
                    listings.push(disasm);
                }
                Mode::Ebpf => {
                    edge(
                        graph,
                        "image_ebpf",
                        &[&image, &layout],
                        &[&bpf, &aot_layout],
                        &[obj],
                        None,
                        &[
                            arg("images", &images)?,
                            arg("bpf", &bpf)?,
                            arg("layout", &aot_layout)?,
                        ],
                    )?;
                    self.prepare(graph, &disasm, &image, &layout)?;
                    self.disassemble(graph, &text, &disasm, "")?;
                    listings.push(disasm);
                }
            }
            upstream.push(image.clone());
            image_members.extend([image, layout]);
            listings.push(text);
        }
        report_inputs.extend(image_members.iter().chain(&listings).map(PathBuf::as_path));
        index_inputs.extend(image_members.iter().map(PathBuf::as_path));
        let recipes = listing.join("recipes.txt");
        let recipe_targets = upstream
            .iter()
            .map(|path| quote(path))
            .collect::<Result<Vec<_>>>()?
            .join(" ");
        edge(
            graph,
            "recipes",
            &[&recipes],
            &[graph_path],
            &[&self.tools.ninja],
            None,
            &[("recipe_targets", recipe_targets)],
        )?;

        let modes = self
            .modes
            .iter()
            .map(Mode::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let report = program.join("report.md");
        report_inputs.push(&recipes);
        edge(
            graph,
            "report",
            &[&report],
            &report_inputs,
            &[obj],
            None,
            &[
                arg("program", &program)?,
                arg("listing", &listing)?,
                arg("linked", &linked)?,
                ("modes", modes.clone()),
            ],
        )?;
        let index = program.join("index.toml");
        index_inputs.push(&report);
        edge(
            graph,
            "index",
            &[&index],
            &index_inputs,
            &[obj],
            None,
            &[arg("program", &program)?, ("modes", modes)],
        )?;
        edge(
            graph,
            "phony",
            &[Path::new(name)],
            &[&index],
            &[],
            None,
            &[],
        )?;
        Ok(())
    }

    fn compile(
        &self,
        graph: &mut Graph,
        rule: &str,
        object: &Path,
        source: &Path,
        depfile: &Path,
        gate: Option<&Path>,
    ) -> Result<()> {
        use std::fmt::Write;
        let outputs = [object, depfile];
        let inputs = [source];
        let tools = [self.tools.clang.as_path()];
        graph.record(&outputs, &inputs, &tools);
        write!(
            graph,
            "build {} | {}: {rule} {} | {}",
            paths(&outputs[..1])?,
            paths(&outputs[1..])?,
            paths(&inputs)?,
            paths(&tools)?
        )?;
        if let Some(gate) = gate {
            write!(graph, " || {}", paths(&[gate])?)?;
        }
        writeln!(
            graph,
            "\n  dependencies = {}\n  depfile_path = {}",
            quote(depfile)?,
            path_text(depfile)?.replace('$', "$$")
        )?;
        Ok(())
    }
    fn prepare(&self, graph: &mut Graph, output: &Path, image: &Path, layout: &Path) -> Result<()> {
        edge(
            graph,
            "prepare_disassembly",
            &[output],
            &[image, layout],
            &[&self.tools.object],
            None,
            &[arg("image", image)?, arg("layout", layout)?],
        )
    }
    fn disassemble(&self, graph: &mut Graph, output: &Path, input: &Path, isa: &str) -> Result<()> {
        edge(
            graph,
            "disassemble",
            &[output],
            &[input],
            &[&self.tools.objdump],
            None,
            &[("isa", isa.to_owned())],
        )
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use super::*;

    // Generate can run without any tool executable and emits just the BPF
    // compile and verification edges when no portable modes are selected.
    #[test]
    fn generate_describes_the_verification_gate_without_running_a_tool() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap();
        let scratch = tempfile::tempdir().unwrap();
        let build = scratch.path().join("build with spaces");
        let tools = Tools {
            clang: "/not an executable/clang".into(),
            lld: "/not an executable/ld.lld".into(),
            objdump: "/not an executable/llvm-objdump".into(),
            ninja: "/not an executable/ninja".into(),
            prevail: "/not an executable/prevail".into(),
            object: "/not an executable/mcu-object".into(),
            jit: "/not an executable/mcu-jit".into(),
        };
        let output = Generate {
            root: &root,
            build: &build,
            sources: &[root.join("tests/diagnostics/xdp_drop.c")],
            modes: &[] as &[Mode],
            tools: &tools,
        }
        .run()
        .unwrap();
        let graph = fs::read_to_string(output.graph).unwrap();
        assert!(graph.contains("BPF COMPILE"));
        assert!(graph.contains("BPF VERIFY"));
        assert!(graph.contains("intermediates/xdp_drop/xdp_drop_bpf.o"));
        assert!(graph.contains("objects/xdp_drop_bpf.o"));
        assert!(graph.contains("'/not an executable/clang'"));
        assert!(!graph.contains("llvm-aot.bin"));
        assert!(!build.join("xdp_drop/objects/xdp_drop_bpf.o").exists());
    }
}
