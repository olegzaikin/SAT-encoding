# Script for generating intermediate inverse problems for SHA-256

script_name="gen_weakM_cnfs.sh"
version="0.0.1"

ln -s ../../sha1-sat/scripts/gen_random_hashes.py .
python3 ./gen_random_hashes.py
ln -s ../../EnCnC/scripts/gen_hash_preimage_instances.py .

for rnd in {17..19}
do
    echo "sha256, rnd=${rnd}"
    for i in {1..31}
    do
        echo "i=$i"
        # Generate a template CNF:
        ./satencoding -f sha256 -t 1 -r ${rnd} -a preimage --equal_toM_bits $i --template_cnf > nossum_sha256_preimage_${rnd}r_${i}bitM_template.cnf
        # Generate instances by adding hashes to the template CNF:
        python3 ./gen_hash_preimage_instances.py ./nossum_sha256_preimage_${rnd}r_${i}bitM_template.cnf hashes_256bit.txt 256 10 --hashvars=./vars_nossum_sha256-${rnd}r --random
    done
    mkdir cnfs_nossum_sha256_${rnd}r_10hashes_interm_new
    mv nossum_sha256_preimage_${rnd}r_*_hashlen* ./cnfs_nossum_sha256_${rnd}r_10hashes_interm_new/
    rm *_template.cnf
done
