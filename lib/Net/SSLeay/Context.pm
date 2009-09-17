
package Net::SSLeay::Context;

use Moose;

use Net::SSLeay;
use Net::SSLeay::Error;

=head1 NAME

Net::SSLeay::Context - OO interface to Net::SSLeay CTX_ methods

=head1 SYNOPSIS

 use Net::SSLeay::Constants qw(OP_ALL FILETYPE_PEM OP_NO_SSLv2);
 use Net::SSLeay::Context;

 # create an SSL object, disable SSLv2
 my $ctx = Net::SSLeay::Context->new;
 $ctx->set_options(OP_ALL & OP_NO_SSLv2);

 # specify path to your CA certificates for verifying peer
 $ctx->load_verify_locations($ca_filename, $db_dir);

 # optional for clients - load our own certificate/key
 $ctx->use_certificate_chain_file($cert_filename);
 $ctx->use_PrivateKey_file($key_filename, FILETYPE_PEM);

 # optional for servers - require peer certificates
 $ctx->set_verify(VERIFY_PEER & VERIFY_FAIL_IF_NO_PEER_CERT);

 # now make SSL objects with these options!
 use Net::SSLeay::SSL;
 my $ssl = Net::SSLeay::SSL->new( ctx => $ctx );

=head1 DESCRIPTION

Every SSL connection has a context, which specifies various options.
You can also specify these options on Net::SSLeay::SSL objects, but
you would normally want to set up as much as possible early on, then
re-use the context to create new SSL handles.

The OpenSSL library initialization functions are called the first time
that a Net::SSLeay::Context object is instantiated.

=cut

has 'ctx' =>
	isa => "Int",
	is => "ro",
	;

=head1 ATTRIBUTES

=over

=item ctx : Int

The raw ctx object.  Use at your own risk.

=item ssl_version: ( undef | 2 | 3 | 10 )

Specify the SSL version to allow.  10 means TLSv1, 2 and 3 mean SSLv2
and SSLv3, respectively.  No options means 'SSLv23'; if you want to
permit the secure protocols only (SSLv3 and TLSv1) you need to use:

  use Net::SSLeay::Constants qw(OP_NO_SSLv2);
  my $ctx = Net::SSLeay::Context->new();
  $ctx->set_options( OP_NO_SSLv2 )

This option must be specified at object creation time.

=back

=cut

has 'ssl_version' =>
	isa => "Int",
	is => "ro",
	;

our $INITIALIZED;

sub BUILD {
	my $self = shift;
	if ( !$INITIALIZED++ ) {
		Net::SSLeay::load_error_strings();
		Net::SSLeay::SSLeay_add_ssl_algorithms();
		Net::SSLeay::randomize();
	}
	if ( ! $self->ctx ) {
		my $ctx = Net::SSLeay::new_x_ctx($self->ssl_version);
		$self->{ctx} = $ctx;
		$self->set_default_verify_paths;
	}
}

sub DESTROY {
	my $self = shift;
	if ( $self->ctx ) {
		$self->free;
		delete $self->{ctx};
	}
}

=head1 METHODS

All of the CTX_ methods in Net::SSLeay are converted to methods of
the Net::SSLeay::Context class.

The documentation that follows is a core set, sufficient for running
up a server and verifying client certificates.

=head2 set_options(OP_XXX & OP_XXX ...)

Set options that apply to this Context.  The valid values and
descriptions can be found on L<SSL_CTX_set_options(3ssl)>; for this
module they must be imported from L<Net::SSLeay::Constants>.

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
VERIFY_CLIENT_ONCE and/or VERIFY_FAIL_IF_NO_PEER_CERT.  If you don't
set this as a server, you cannot later call
C<-E<gt>get_peer_certificate> to find out if the client configured a
certificate.

=cut

use Net::SSLeay::Constants qw(VERIFY_NONE);

has 'verify_cb',
	is => "ro";

sub set_verify {
	my $self = shift;
	my $mode = shift;
	my $callback = shift;
	# always set a callback, unless VERIFY_NONE "is set"
	my $real_cb = $mode == VERIFY_NONE ? undef : sub {
		my ($preverify_ok, $x509_store_ctx) = @_;
		if ( $callback ) {
			my $x509_ctx = Net::SSLeay::X509::Context->new(
				x509_store_ctx => $x509_store_ctx,
				);
			my $cert = $x509_ctx->get_current_cert;
			$callback->($preverify_ok, $cert);
		}
		else {
			$preverify_ok;
		}
	};
	$self->_set_verify($mode, $real_cb);
	&Net::SSLeay::Error::die_if_ssl_error("set_verify");
}

sub _set_verify {
	my $self = shift;
	my $mode = shift;
	my $real_cb = shift;
	my $ctx = $self->ctx;
	$self->{verify_cb} = $real_cb;
	Net::SSLeay::CTX_set_verify($ctx, $mode, $real_cb);
}

=head2 use_certificate_file($filename, $type)

C<$filename> is the name of a local file.  This becomes your local
cert - client or server.

C<$type> may be FILETYPE_PEM or FILETYPE_ASN1.

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

sub get_cert_store {
	my $self = shift;
	require Net::SSLeay::X509::Store;
	my $store = Net::SSLeay::CTX_get_cert_store($self->ctx),
	&Net::SSLeay::Error::die_if_ssl_error("get_cert_store");
	Net::SSLeay::X509::Store->new( x509_store => $store );
}

use Net::SSLeay::Functions "ctx";

1;

__END__

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
