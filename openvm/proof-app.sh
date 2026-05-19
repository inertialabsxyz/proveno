cargo openvm keygen
cargo openvm prove app --bin luai-openvm --input /tmp/openvm-1.json
cargo openvm verify app --proof luai-openvm.app.proof
cargo run --bin luai-openvm-packager -- luai-openvm.app.proof /tmp/dry_result.json luai-proof.bin
echo "Wire-format proof: $(wc -c < luai-proof.bin) bytes"
