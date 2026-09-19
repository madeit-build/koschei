# Native `<sealedinput>` for Ladybird

The patch series against Ladybird `1010a932`. See `docs/specs/native-ladybird-design.md`.

    LADYBIRD_DIR=~/code/scratch/ladybird native/ladybird/apply-and-build.sh   # ~1 h cold, minutes warm
    LADYBIRD_DIR=~/code/scratch/ladybird native/ladybird/run-demo.sh          # writes docs/research/assets/ladybird-*.png and native-demo.jsonl

`run-demo.sh` exits non-zero unless the recipient logged at least one `sealed-input.unseal` with `outcome: ok`.
