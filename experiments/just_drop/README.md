# Just Drop

The baseline measures XDP dispatch followed by an unconditional `XDP_DROP`. It consumes no packet fields and calls no helper.

Build the portable modes with `cargo run --locked -p mcu -- build -c just_drop`.
