#!/usr/bin/perl -w

use strict;
use Test::More qw(no_plan);
use FindBin qw($Bin);

BEGIN {
      use_ok("Net::SSLeay::SSL");
}

use Net::SSLeay::Constants  qw(OP_ALL VERIFY_NONE FILETYPE_PEM);

my $destroyed;
my $ssl_id;
{
	my $ssl = Net::SSLeay::SSL->new;

	isa_ok($ssl, "Net::SSLeay::SSL", "new Net::SSLeay::SSL");

	$ssl_id = $ssl->ssl;
	ok($ssl_id, "has a ssl");

	$ssl->set_options(OP_ALL);
	is($ssl->get_options, OP_ALL,
	   "takes options like a good little ssl");

	eval {
		$ssl->use_certificate_file(
			"$Bin/certs/no-such-server-cert.pem",
			FILETYPE_PEM,
			);
	};
	isa_ok($@, "Net::SSLeay::Error", "exception");
	isa_ok($@->next, "Net::SSLeay::Error", "exception trace");
	#diag $@;

	my $old_sub = \&Net::SSLeay::SSL::free;
	no warnings 'redefine';
	*Net::SSLeay::SSL::free = sub {
		$destroyed = $_[0]->ssl;
		$old_sub->(@_);
	};
}
is($destroyed, $ssl_id, "Called SSL_free");

# Local Variables:
# mode:cperl
# indent-tabs-mode: t
# cperl-continued-statement-offset: 8
# cperl-brace-offset: 0
# cperl-close-paren-offset: 0
# cperl-continued-brace-offset: 0
# cperl-continued-statement-offset: 8
# cperl-extra-newline-before-brace: nil
# cperl-indent-level: 8
# cperl-indent-parens-as-block: t
# cperl-indent-wrt-brace: nil
# cperl-label-offset: -8
# cperl-merge-trailing-else: t
# End:
# vim: filetype=perl:noexpandtab:ts=3:sw=3
