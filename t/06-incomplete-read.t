#!/usr/bin/perl
#
#  t/06-incomplete-read.t - test behaviour around incomplete reads
#
#  If the amount of data ready on a socket is less than the complete
#  rest of the SSL packet, then you get an input ready event, but no
#  data is returned by the read: thus mimicking the behaviour of a
#  hangup.  This test script is to prove this and to try to identify
#  ways forward.
#
# Copyright (C) 2010  NZ Registry Services
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the Artistic License 2.0 or later.  You should
# have received a copy of the Artistic License the file COPYING.txt.
# If not, see <http://www.perlfoundation.org/artistic_license_2_0>

use Test::More no_plan;

use strict;
use warnings;

use Net::SSLeay::OO;
use IO::Handle;
use FindBin qw($Bin);

my $ctx = Net::SSLeay::OO::Context->new;

our $DEBUG = $ENV{DEBUG_SSL};

use Net::SSLeay::OO::Constants qw(ERROR_WANT_READ ERROR_WANT_WRITE
	ERROR_NONE ERROR_WANT_CONNECT
	FILETYPE_PEM
	MODE_ENABLE_PARTIAL_WRITE
	MODE_ACCEPT_MOVING_WRITE_BUFFER );

$ctx->set_default_passwd_cb( sub {"secr1t"} );

my $client = Net::SSLeay::OO::SSL->new( ctx => $ctx );
my $server = Net::SSLeay::OO::SSL->new( ctx => $ctx );
$server->use_certificate_file( "$Bin/certs/server-cert.pem", FILETYPE_PEM );
$server->use_PrivateKey_file( "$Bin/certs/server-key.pem", FILETYPE_PEM );

# compared with the previous test, we add an intermediate buffer
# stage, which can be used to trickle information into the server's
# input buffers.
pipe( reader_server, writer_inbetween ) or die $!;
pipe( reader_inbetween, writer_client ) or die $!;
pipe( reader_client, writer_server ) or die $!;

$client->set_rfd( fileno(reader_client) );
$client->set_wfd( fileno(writer_client) );
$server->set_rfd( fileno(reader_server) );
$server->set_wfd( fileno(writer_server) );

$_->blocking(0) for (
	\*reader_server, \*writer_server, \*reader_client,
	\*writer_client, \*reader_inbetween, \*writer_inbetween,
	);

our @read_buffer;
our $flush_close;
my $move_inbetween;
$move_inbetween = sub {
	my $rv = read(reader_inbetween, my $data, 4096);
	if ( length $data ) {
		diag("inbetween read ".length($data)." bytes") if $DEBUG;
		push @read_buffer, $data;
	}
	else {
		diag("inbetween read returned: "
			     .(defined($rv)?"$rv":"undef: $!")) if $DEBUG;

		# it seems every way of reading filehandles in unix
		# has its own set of idiosynchronacies...
		if ( !$rv and !$!{EAGAIN} ) {
			diag("inbetween read eof: closing at end of buffer")
				if $DEBUG;
			$flush_close = 1;
		}
	}
	if ( @read_buffer ) {
		my $rec = shift @read_buffer;
		my $written = syswrite(writer_inbetween, $rec, 4096);
		if ( $written ) {
			diag("inbetween wrote ".length($data)." bytes")
				if $DEBUG;
		}
		if ( $written < length($rec) ) {
			substr($rec, 0, $written, "");
			unshift @read_buffer, $rec;
		}
	}
	elsif ( $flush_close ) {
		diag("inbetween: closed")
			if $DEBUG;
		close writer_inbetween;
		$move_inbetween = sub { };
	}
};

# SSL_MODE_* not imported by Net::SSLeay
#  SSL_MODE_ENABLE_PARTIAL_WRITE - write single SSL records at a time.
#  SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER - ``This is not the default to
#          avoid the misconception that non-blocking SSL_write()
#          behaves like non-blocking write().'' - with it, it seems
#          to... odd.
my $mode = ( MODE_ENABLE_PARTIAL_WRITE | MODE_ACCEPT_MOVING_WRITE_BUFFER );
$server->set_mode($mode);
$client->set_mode($mode);

$client->set_connect_state;
$server->set_accept_state;
my $needy;

diag("about to handshake with self") if $DEBUG;
do {
	$needy = 0;
	for my $x ( $client, $server ) {

		diag("$x->do_handshake") if $DEBUG;
		my $error = $x->do_handshake;
		if ($error) {
			my $want = $x->get_error($error);
			if ( $want == ERROR_WANT_READ ) {
				$needy = 1;
				$move_inbetween->();
			}
			elsif ( $want == ERROR_NONE ) {
			}
			else {
				diag("want?  $want");
			}
		}
	}
} while ($needy);

pass("Successfully shook hands with self");

my $data = "Some example data\n" x ( 1024 * 5 )
	;    # just too big for 1 SSL/TLS record

my $o          = 0;
my $l          = length $data;
my $bytes_read = 0;
my @read_chunks;
my $writes;
my $retry;
my ($hungup, $saw_hangup);
while ( !$saw_hangup ) {
	if ( $o < $l ) {
		$retry ||= sub {
			diag( "attempting to write " . ( $l - $o ) . " bytes"
			      ) if $DEBUG;
			$client->write( substr( $data, $o, ( $l - $o ) ) );
		};
		my $written = $retry->();
		if ( $written > 0 ) {
			diag("wrote $written bytes")
				if $DEBUG;
			$writes++;
			$o += $written;
			undef($retry);
			next;
		}
	}
	elsif ( !$hungup ) {
		$hungup++;
		diag("client shutdown") if $DEBUG;
		$client->shutdown;
		close(writer_client);
	}
	my $chunk = $server->read;
	if ( defined $chunk and length $chunk ) {
		diag("read ".length($chunk)." bytes") if $DEBUG;
		$bytes_read += length $chunk;
		push @read_chunks, $chunk;
	}
	else {
		diag("read returned ".(defined($chunk)?"0 bytes":"undef"))
			if $DEBUG;

		# ... and here we have it, if there is a 0 length
		# return it is an eof, otherwise it is likely EAGAIN.
		# (just like read)
		if ( defined($chunk) ) {
			$saw_hangup = 1;
			diag("saw client eof!") if $DEBUG;
		}
		else {
			$move_inbetween->();
		}
	}
}

is( $bytes_read, $l, "Got all data back" );
is( join( "", @read_chunks ), $data, "Data the same" );
cmp_ok( $writes, ">", 1, "More than one write was needed" );

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
