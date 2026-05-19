cd compiler
cargo run -- ../examples/prover.lua /tmp/compiled.json
cd ../prover
cargo run -- /tmp/compiled.json /tmp/dry_result.json
cd ../openvm
echo "encode inputs for openvm"
cargo run --bin luai-openvm-encoder -- /tmp/compiled.json /tmp/dry_result.json
echo "run circuit"
cargo openvm run --bin luai-openvm --input /tmp/openvm-1.json
echo "prove"
cargo openvm keygen
cargo openvm prove app --bin luai-openvm --input /tmp/openvm-1.json
cargo openvm verify app --proof luai-openvm.app.proof
echo "package"
cargo run --bin luai-openvm-packager -- luai-openvm.app.proof /tmp/dry_result.json luai-proof.bin
echo "Wire-format proof: $(wc -c < luai-proof.bin) bytes"
