#!/usr/bin/perl

use Test::More no_plan;

use strict;
use warnings;

use Net::SSLeay::OO;
use IO::Handle;
use FindBin qw($Bin);

my $ctx = Net::SSLeay::Context->new;

our $DEBUG = $ENV{DEBUG_SSL};

use Net::SSLeay::Constants qw(ERROR_WANT_READ ERROR_WANT_WRITE
			      ERROR_NONE ERROR_WANT_CONNECT
			      FILETYPE_PEM
			      );

$ctx->set_default_passwd_cb(sub { "secr1t" });

my $client = Net::SSLeay::SSL->new( ctx => $ctx );
my $server = Net::SSLeay::SSL->new( ctx => $ctx );
$server->use_certificate_file("$Bin/certs/server-cert.pem", FILETYPE_PEM);
$server->use_PrivateKey_file("$Bin/certs/server-key.pem", FILETYPE_PEM);

pipe(RS, WC) or die $!;
pipe(RC, WS) or die $!;

$client->set_rfd(fileno(RC)); $client->set_wfd(fileno(WC));
$server->set_rfd(fileno(RS)); $server->set_wfd(fileno(WS));

$_->blocking(0) for (\*RS, \*WS, \*RC, \*WC);
# SSL_MODE_* not imported by Net::SSLeay
#  1 = SSL_MODE_ENABLE_PARTIAL_WRITE - write SSL records at a time.
#  2 = SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER - ``This is not the default
#          to avoid the misconception that non-blocking SSL_write() behaves
#          like non-blocking write().'' - with it, it seems to... odd.
$server->set_mode(3);
$client->set_mode(3);

$client->set_connect_state;
$server->set_accept_state;
my $needy;
#diag("about to handshake with self");
do {
	$needy = 0;
	for my $x ( $client, $server ) {
		#diag("$x->do_handshake");
		my $error = $x->do_handshake;
		if ( $error ) {
			my $want = $x->get_error($error);
			if ( $want == ERROR_WANT_READ ) {
				$needy = 1;
			}
			elsif ( $want == ERROR_NONE ) {
			}
			else {
				diag("want?  $want");
			}
		}
	}
}
	while ($needy);

pass("Successfully shook hands with self");

my $data = "Some example data\n" x (1024 * 5);  # just too big for 1 SSL/TLS record

$client->write("GET /\r\n\r\n");
my $req = $server->read;

my $o = 0;
my $l = length $data;
my $bytes_read = 0;
my @read_chunks;
my $writes;
my $retry;
while ( $bytes_read < $l ) {
	if ( $o < $l ) {
		$retry ||= sub {
			diag("attempting to write ".($l-$o)." bytes")
				if $DEBUG;
			$server->write(substr($data, $o, ($l-$o)));
		};
		my $written = $retry->();
		if ( $written > 0) {
			diag("wrote $written bytes")
				if $DEBUG;
			$writes++;
			$o += $written;
			undef($retry);
			next;
		}
	}
	my $chunk = $client->read;
	if ( length $chunk ) {
		$bytes_read += length $chunk;
		push @read_chunks, $chunk;
	}
}

is($bytes_read, $l, "Got all data back");
is(join("", @read_chunks), $data, "Data the same");
cmp_ok($writes, ">", 1, "More than one write was needed");

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
