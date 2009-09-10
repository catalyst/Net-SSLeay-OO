
package TestCerts;

my $cert_dir = "t/certs";

print STDERR "*** making test certificates\n";
my $output = `$cert_dir/make-test-certs.sh 0</dev/null 2>&1`;
if ($? != 0) {
	print STDERR "*** error making test certificates:\n";
	print $output;
}
else {
	print STDERR "*** done making test certificates\n";
}

1;
