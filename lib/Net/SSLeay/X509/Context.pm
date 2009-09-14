
package Net::SSLeay::X509::Context;

use Moose;

has 'x509_store_ctx' =>
	isa => 'Int',
	is => "ro",
	required => 1,
	;

use Net::SSLeay::Functions sub {
	my $code = shift;
	sub {
		my $self = shift;
		$code->($self->x509_store_ctx, @_);
	};
};

sub get_current_cert {
	my $self = shift;
	my $x509 = Net::SSLeay::X509_STORE_CTX_get_current_cert(
		$self->x509_store_ctx,
		);
	if ( $x509 ) {
		require Net::SSLeay::X509;
		Net::SSLeay::X509->new(x509 => $x509, no_rvinc => 1);
	}
}

# getting all these right is made harder by the lack of OpenSSL docs
# for these methods...

# get_error()
# get_error_depth()
# get_ex_data()
# set_cert()
# set_error()
# set_ex_data()
# set_flags()

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
