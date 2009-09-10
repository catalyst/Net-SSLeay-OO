#!/usr/bin/perl -w

use strict;
use Test::More qw(no_plan);
use FindBin qw($Bin);

BEGIN {
      use_ok("Net::SSLeay::Context");
}

use Net::SSLeay::Constants  qw(OP_ALL VERIFY_NONE FILETYPE_PEM);

my $destroyed;
my $ctx_id;
{
	my $ctx = Net::SSLeay::Context->new;

	isa_ok($ctx, "Net::SSLeay::Context", "new Net::SSLeay::Context");

	$ctx_id = $ctx->ctx;
	ok($ctx_id, "has a ctx");

	$ctx->set_options(OP_ALL);
	is($ctx->get_options, OP_ALL,
	   "takes options like a good little ctx");

	$ctx->load_verify_locations("", "$Bin/certs");

	eval {
		$ctx->use_certificate_chain_file
			("$Bin/certs/no-such-server-cert.pem");
	};
	isa_ok($@, "Net::SSLeay::Error", "exception");
		#&& diag $@;

	$ctx->set_default_passwd_cb(sub { "secr1t" });
	$ctx->use_PrivateKey_file
		("$Bin/certs/server-key.pem", FILETYPE_PEM);
	$ctx->use_certificate_chain_file("$Bin/certs/server-cert.pem");

	my $store = $ctx->get_cert_store;
	isa_ok($store, "Net::SSLeay::X509::Store", "get_cert_store()");

	my $old_sub = \&Net::SSLeay::Context::free;
	no warnings 'redefine';
	*Net::SSLeay::Context::free = sub {
		$destroyed = $_[0]->ctx;
		$old_sub->(@_);
	};
}
is($destroyed, $ctx_id, "Called CTX_free");

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
