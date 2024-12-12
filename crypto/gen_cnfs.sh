# Script for generating inverse problems for SHA-256

script_name="gen_cnfs.sh"
version="0.0.1"

ln -s ../../sha1-sat/scripts/gen_random_hashes.py .
python3 ./gen_random_hashes.py
ln -s ../../EnCnC/scripts/gen_hash_preimage_instances.py .

for rnd in {17..19}
do
    echo "sha256, rnd=${rnd}"
    # Generate a template CNF:
    ./satencoding -f sha256 -t 1 -r ${rnd} -a preimage --template_cnf > nossum_sha256_preimage_${rnd}r_template.cnf
    # Generate instances by adding hashes to the template CNF:
    python3 ./gen_hash_preimage_instances.py ./nossum_sha256_preimage_${rnd}r_template.cnf hashes_256bit.txt 256 10 --hashvars=./vars_nossum_sha256-${rnd}r --random
    mkdir cnfs_nossum_sha256_${rnd}r_10hashes
    mv nossum_sha256_preimage_${rnd}r_*_hashlen* ./cnfs_nossum_sha256_${rnd}r_10hashes/
    rm *_template.cnf
done
