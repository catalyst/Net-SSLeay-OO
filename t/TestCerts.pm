package TestCerts;
use FindBin qw($Bin);

my $cert_dir = "$Bin/certs";

system("$cert_dir/make-test-certs.sh 0</dev/null") == 0;
