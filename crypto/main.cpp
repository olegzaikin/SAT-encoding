#include "sha1.h"
#include "sha256.h"
#include "md4.h"
#include "util.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <getopt.h>
#include <time.h>
#include <string>

std::string version = "1.1.2";

enum FuncType {
    FT_MD4,
    FT_SHA1,
    FT_SHA256,
    FT_NONE
};

enum AnalysisType {
    AT_PREIMAGE,
    AT_COLLISION,
    AT_NONE
};

/* config options */
int cfg_use_xor_clauses;
Formula::MultiAdderType cfg_multi_adder_type;
int cfg_rand_target;
int cfg_print_target;
FuncType cfg_function;
AnalysisType cfg_analysis;
int fixed_bits;
int cfg_equal_toM_bits;

void preimage(int rounds)
{
    MDHash *f;

    if ( cfg_function == FT_SHA1 )
        f = new SHA1(rounds);
    else if ( cfg_function == FT_SHA256 )
        f = new SHA256(rounds);
    else if ( cfg_function == FT_MD4 )
        f = new MD4(rounds);
    else
    {
        fprintf(stderr, "Invalid function type!\n");
        return;
    }

    if ( cfg_use_xor_clauses ) f->cnf.setUseXORClauses();
    if ( cfg_multi_adder_type != Formula::MAT_NONE ) f->cnf.setMultiAdderType(cfg_multi_adder_type);
    f->cnf.setEqualToMbits(cfg_equal_toM_bits);

    f->encode();

    unsigned w[rounds];
    unsigned hash[f->outputSize];

    if ( cfg_rand_target == 1 )
    {
        /* Generate a random pair of input/target */
        for( int i=0; i<f->inputSize; i++ )
            w[i] = lrand48();

        if ( cfg_function == FT_SHA1 )
            sha1_comp(w, hash, rounds);
        else if ( cfg_function == FT_SHA256 )
            sha256_comp(w, hash, rounds);
        else if ( cfg_function == FT_MD4 )
            md4_comp(w, hash, rounds);

        if ( cfg_print_target )
        {
            for( int i=0; i<f->inputSize; i++ )
                printf("%08x ", w[i]);
            printf("\n");

            for( int i=0; i<f->outputSize; i++ )
                printf("%08x ", hash[i]);
            printf("\n");

            return;
        }
    }
    else if ( cfg_rand_target == 0 )
    {
        /* Read the input/target from stdin */
        int rcnt = 0;
        for( int i=0; i<f->inputSize; i++ )
            rcnt += scanf("%x", &w[i]);
        assert( rcnt == f->inputSize );

        rcnt = 0;
        for( int i=0; i<f->outputSize; i++ )
            rcnt += scanf("%x", &hash[i]);
        assert( rcnt == f->outputSize );
    }
    // all 0s
    else if ( cfg_rand_target == 2 )
    {
        for ( int i=0; i<f->outputSize; i++ ) hash[i] = 0x0;
    }
    // all 1s
    else if ( cfg_rand_target == 3 )
    {
        for ( int i=0; i<f->outputSize; i++ ) hash[i] = 0xffffffff;
    }

    /* Set hash target bits */
    f->fixOutput(hash);

    /* Fix input bits (if asked) */
    for(int i=0; i<fixed_bits; i++)
    {
        int r = i / 32;
        int c = i % 32;
        f->cnf.fixedValue(&(f->w[r][c]), (w[r] >> c) & 1, 1);
    }

    /* Printing out the instance */
    f->cnf.dimacs();

    delete f;
}

void display_usage()
{
    printf("USAGE: ./satencoding {number_of_rounds}\n"
            "  --help or -h                             Prints this message\n"
            "  --version or -v                          Prints the version\n"
            "  --xor                                    Use XOR clauses (default: off)\n"
            "  --adder_type or -A {two_operand | counter_chain | espresso | dot_matrix}\n"
            "                                           Specifies the type of multi operand addition encoding (default: espresso)\n"
            "  --target or -t {random | stdin | 0 | 1}  Hash target - random, stdin, all 0s, or all 1s (default: random)\n"
            "                                           random: Generates a random input/target pair\n"
            "                                           stdin: Reads the target from stdin (space separated hex values)\n"
            "  --rounds or -r {int(16..80)}             Number of rounds in your function\n"
            "  --function or -f {md4 | sha1 | sha256}   Type of function under analysis (default: sha1)\n"
            "  --analysis or -a {preimage | collision}  Type of analysis (default: preimage)\n"
            "  --print_target                           Prints the randomly generated message/target and exits (--target should be set to random mode)\n"
            "  --equal_toM_bits -M {int(0..32)}         Number of message bits used in the last round (remaining are 0s)\n"
            "  --fix or -F {int(0..512)}                Fixes the given number (k) of input bits (in the range 0..(k-1)) (default: 0)\n"
          );
}

void display_version()
{
    printf("satencoding of version %s \n", version.c_str());
}

int main(int argc, char **argv)
{
    unsigned long seed = time( NULL );

    /* Arguments default values */
    cfg_use_xor_clauses = 0;
    cfg_multi_adder_type = Formula::MAT_NONE;
    cfg_rand_target = 1;
    cfg_print_target = 0;
    cfg_function = FT_SHA1;
    cfg_analysis = AT_PREIMAGE;
    int rounds = -1;
    fixed_bits = 0;
    cfg_equal_toM_bits = 32; // by default no bits are assigned to 0

    struct option long_options[] =
    {
        /* flag options */
        {"xor",           no_argument, &cfg_use_xor_clauses,   1},
        {"print_target",  no_argument, &cfg_print_target,      1},
        /* valued options */
        {"rounds",   required_argument, 0, 'r'},
        {"fix",   required_argument, 0, 'F'},
        {"function", required_argument, 0, 'f'},
        {"analysis", required_argument, 0, 'a'},
        {"adder_type", required_argument, 0, 'A'},
        {"target", required_argument, 0, 't'},
        {"equal_toM_bits", required_argument, 0, 'M'},
        {"help",     no_argument,       0, 'h'},
        {"version",  no_argument,       0, 'v'},
        {0, 0, 0, 0}
    };

    /* Process command line */
    int c, option_index;
    while( (c = getopt_long(argc, argv, "a:r:f:F:A:t:M:h:v", long_options, &option_index)) != -1 )
    {
        switch ( c )
        {
            case 0:
                /* If this option set a flag, do nothing else now. */
                if ( long_options[option_index].flag != 0 )
                    break;
                printf("option %s", long_options[option_index].name);
                if ( optarg )
                    printf (" with arg %s", optarg);
                printf ("\n");
                break;

            case 'r':
                rounds = atoi(optarg);
                break;

            case 'F':
                fixed_bits = atoi(optarg);
                if (fixed_bits < 0 || fixed_bits > 512)
                {
                    fprintf(stderr, "Inavlid number of input bits to fix\n");
                    return 1;
                }
                break;

            case 'a':
                cfg_analysis = strcmp(optarg, "preimage") == 0 ? AT_PREIMAGE :
                    strcmp(optarg, "collision") == 0 ? AT_COLLISION : 
                    AT_NONE;
                if ( cfg_analysis == AT_NONE )
                {
                    fprintf(stderr, "Invalid or missing analysis type!\nUse -a or --analysis\n");
                    return 1;
                }
                break;

            case 'f':
                cfg_function = strcmp(optarg, "sha1") == 0 ? FT_SHA1 :
                    strcmp(optarg, "sha256") == 0 ? FT_SHA256 : 
                    strcmp(optarg, "md4") == 0 ? FT_MD4 : 
                    FT_NONE;
                if ( cfg_function == FT_NONE )
                {
                    fprintf(stderr, "Invalid or missing function type!\nUse -f or --function\n");
                    return 1;
                }
                break;

            case 'A':
                cfg_multi_adder_type =
                    strcmp(optarg, "two_operand") == 0 ? Formula::TWO_OPERAND :
                    strcmp(optarg, "counter_chain") == 0 ? Formula::COUNTER_CHAIN :
                    strcmp(optarg, "espresso") == 0 ? Formula::ESPRESSO :
                    strcmp(optarg, "dot_matrix") == 0 ? Formula::DOT_MATRIX :
                    Formula::MAT_NONE;
                if ( cfg_multi_adder_type == Formula::MAT_NONE )
                {
                    fprintf(stderr, "Invalid or missing multi-adder type!\nUse -h to see the optionsi\n");
                    return 1;
                }
                break;

            case 't':
                if (strcmp(optarg, "stdin") == 0) cfg_rand_target = 0;
                else if (strcmp(optarg, "random") == 0) cfg_rand_target = 1;
                else if (strcmp(optarg, "0") == 0) cfg_rand_target = 2;
                else if (strcmp(optarg, "1") == 0) cfg_rand_target = 3;
                else cfg_rand_target = -1;
                if (cfg_rand_target == -1)
                {
                    fprintf(stderr, "Invalid or missing target type!\nUse -t or --target with random or stdin\n");
                    return 1;
                }
                break;

            case 'M':
                cfg_equal_toM_bits = atoi(optarg);
                if (cfg_equal_toM_bits < 0 || cfg_equal_toM_bits > 32)
                {
                    fprintf(stderr, "Inavlid value of cfg_equal_toM_bits\nMust be >= 0 and <= 32.");
                    return 1;
                }
                break;

            case 'h':
                display_usage();
                return 1;

            case 'v':
                display_version();
                return 1;

            case '?':
/*                if (optopt == 'r')
                      fprintf (stderr, "Please specify the number of rounds with -r.\n");
                  else if (isprint (optopt))
                      fprintf (stderr, "Unknown option `-%c'.\n", optopt);
                  else
                      fprintf (stderr,
                              "Unknown option character `\\x%x'.\n",
                              optopt);*/
                return 1;

            default:
                abort ();
        }
    }

    if ( rounds == -1 )
    {
        fprintf(stderr, "Number of rounds is required! Use -r or --rounds\n");
        return 1;
    }

    srand(seed);
    srand48(rand());

    if ( cfg_analysis == AT_PREIMAGE )
        preimage(rounds);
    else
    {
        printf("Not supported yet!\n");
    }


    return 0;
}
