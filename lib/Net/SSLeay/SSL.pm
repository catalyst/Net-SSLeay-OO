
package Net::SSLeay::SSL;

use Moose;
use Net::SSLeay::Context;

=head1 NAME

Net::SSLeay::SSL - OO interface to Net::SSLeay methods

=head1 SYNOPSIS

 use Net::SSLeay::Constants qw(OP_ALL);
 use Net::SSLeay::SSL;

 my $ssl = Net::SSLeay::SSL->new;
 $ssl->set_fd(fileno($socket));

=head1 DESCRIPTION

This module adds some OO niceties to using the Net::SSLeay / OpenSSL
SSL objects.  For a start, you get a blessed object rather than an
integer to work with, so you know what you are dealing with.

=cut

=head1 ATTRIBUTES

=over

=item ssl : Int

The raw *SSL pointer.  Use at your own risk.

=cut

has 'ssl' =>
	isa => "Int",
	is => "ro",
	required => 1,
	lazy => 1,
	default => sub {
		my $self = shift;
		Net::SSLeay::new($self->ctx->ctx);
	},
	;

=item ctx : Context

A Net::SSLeay::Context object.  Automatically created if not assigned
on creation of the Net::SSLeay::SSL.

=cut

has 'ctx' =>
	isa => "Net::SSLeay::Context",
	is => "ro",
	required => 1,
	default => sub {
		Net::SSLeay::Context->new();
	},
	;

=back

=cut

sub DESTROY {
	my $self = shift;
	if ( $self->ssl ) {
		$self->free;
		delete $self->{ssl};
	}
}

=head1 METHODS

All of the methods in Net::SSLeay which are not obviously a part of
some other class are converted to methods of the Net::SSLeay::SSL
class.

The documentation that follows is a core set, sufficient for running
up a server and verifying client certificates.  However most functions
from the OpenSSL library are actually imported.

=cut

=head2 set_options(OP_XXX & OP_XXX ...)

Set options that apply to this Context.  The valid values and
descriptions can be found on L<SSL_CTX_set_options(3ssl)>; for this
module they must be imported from L<Net::SSLeay::Constants>.

Returns the active bitmask.

=head2 get_options()

Returns the current options bitmask; mask with the option you're
interested in to see if it is set:

  unless ($ctx->get_options & OP_NO_SSLv2) {
      die "SSL v2 was not disabled!";
  }

=head2 load_verify_locations($filename, $path)

Specify where CA certificates in PEM format are to be found.
C<$filename> is a single file containing one or more certificates.
C<$path> refers to a directory with C<9d66eef0.1> etc files as would
be made by L<c_rehash>.  See L<SSL_CTX_load_verify_locations(3ssl)>.

=head2 set_verify($mode, [$verify_callback])

Mode should be either VERIFY_NONE, or a combination of VERIFY_PEER,
VERIFY_CLIENT_ONCE and/or VERIFY_FAIL_IF_NO_PEER_CERT.  The callback
is

=cut

sub BUILD {
	my $self = shift;
	$self->ssl;
}

use Net::SSLeay::Constants qw(VERIFY_NONE);

sub set_verify {
	my $self = shift;
	my $mode = shift;
	my $callback = shift;
	# always set a callback, unless VERIFY_NONE "is set"
	my $real_cb = $mode == VERIFY_NONE ? 0 : sub {
		my ($preverify_ok, $x509_ctx) = @_;
		if ( $callback ) {
			my $x509_ctx = Net::SSLeay::X509::Context->new(
				ctx => $x509_ctx,
				);
			$callback->($preverify_ok, $x509_ctx);
		}
	};
	Net::SSLeay::set_verify($self->ctx, $mode, $real_cb);
}

=head2 use_certificate_file($filename, $type)

C<$filename> is the name of a local file.  This becomes your local
cert - client or server.

C<$type> may be SSL_FILETYPE_PEM or SSL_FILETYPE_ASN1.

=head2 use_certificate_chain_file($filename)

C<$filename> is the name of a local PEM file, containing a chain of
certificates which lead back to a valid root certificate.  This is
probably the option you really should use for flexible (albeit PEM
only) use.

=head2 use_PrivateKey_file($filename, $type);

If using a certificate, you need to specify the private key of the end
of the chain.  Specify it here; set C<$type> as with
C<use_certificate_file>

=cut

use Net::SSLeay::Functions 'ssl';

1;

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
