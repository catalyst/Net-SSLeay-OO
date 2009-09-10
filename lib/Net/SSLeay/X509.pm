
package Net::SSLeay::X509;

use Moose;

has 'x509' =>
	isa => 'Int',
	is => "ro",
	required => 1,
	;

#sub DESTROY {
	#my $self = shift;
	#$self->free;
#}

# free()
# get_ext()
# get_ext_by_NID()
# get_notAfter()
# get_notBefore()

BEGIN {
	no strict 'refs';
	for my $nameFunc ( qw(subject_name issuer_name subjectAltNames) ) {
		my $get = "get_$nameFunc";
		my $sslfunc = "Net::SSLeay::X509_$get";
		*$get = sub {
			my $self = shift;
			require Net::SSLeay::X509::Name;
			my $name = &$sslfunc($self->x509);
			Net::SSLeay::X509::Name->new( x509_name => $name );
		};
	}
}

use Net::SSLeay::Functions sub {
	my $code = shift;
	sub {
		my $self = shift;
		$code->($self->x509, @_);
	};
};

# load_cert_crl_file()
# load_cert_file()
# load_crl_file()
# verify_cert_error_string()

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
