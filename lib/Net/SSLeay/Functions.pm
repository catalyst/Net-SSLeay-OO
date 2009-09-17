
package Net::SSLeay::Functions;

use Net::SSLeay;

my %prefixes = (
	"" => "Net::SSLeay::SSL",
	BIO => "Net::SSLeay::BIO",
	CIPHER => "Net::SSLeay::Cipher",
	COMP => "Net::SSLeay::Compression",
	CTX => "Net::SSLeay::Context",
	DH => "Net::SSLeay::KeyType::DH",
	ENGINE => "Net::SSLeay::Engine",
	ERR => "Net::SSLeay::Error",
	EVP_PKEY => "Net::SSLeay::PrivateKey",
	#MD2 => undef,
	#MD4 => undef,
	#MD5 => undef,
	PEM => "Net::SSLeay::PEM",
	#P_ASN1_UTCTIME => undef,
	RAND => "Net::SSLeay::PRNG",
	RSA => "Net::SSLeay::KeyType::RSA",
	SESSION => "Net::SSLeay::Session",
	#X509V3_EXT => undef,
	X509_NAME => "Net::SSLeay::X509::Name",
	X509_STORE => "Net::SSLeay::X509::Store",
	X509_STORE_CTX => "Net::SSLeay::X509::Context",
	X509 => "Net::SSLeay::X509",
	);

my %ready;

while ( my ($sym, $glob) = each %Net::SSLeay:: ) {
	my $display = $sym =~ /ERRZX/;
	print STDERR "Considering $sym: " if $display;
	my ($sub_pkg, $method) =
		$sym =~ m{^(?:([A-Z][A-Z0-9]*(?:_[A-Z][A-Z0-9]*)*)_)?
			  ([a-z]\w+)$}x;
	if ( !$method ) {
		print STDERR "didn't match pattern, next\n" if $display;;
		next;
	}
	use Data::Dumper;
	if ( ! *{"Net::SSLeay::$sym"}{CODE} ) {
		print STDERR "not a func, next\n" if $display;;
		next;
	}
	if ($method eq "new") {
		print STDERR "it's 'new', next\n" if $display;;
		next;
	}
	my $pkg = $prefixes{$sub_pkg||""};
	if (!$pkg) {
		print STDERR "destination package undefined; next\n" if $display;;
		next;
	}
	print STDERR " => belongs in $pkg as $method\n" if $display;;
	if ( *{$glob}{CODE} ) {
		$ready{$pkg}{$method} = \&{*$glob};
	}
	else {
		$ready{$pkg}{$method} = sub {
			goto \&{"Net::SSLeay::$sym"};
		};
	}
}

sub import {
	my $pkg = shift;
	my $caller = caller;
	my $install = shift || sub{ shift };
	if ( !ref $install ) {
		my $att = $install;
		$install = sub {
			my $code = shift;
			my $method = shift;
			sub {
				my $self = shift;
				my @rv;
				my $pointer = $self->$att
					or die "no pointer in $self; this"
		." object may be being used outside of its valid lifetime";
				if ( wantarray ) {
					@rv = $code->($pointer, @_);
				}
				else {
					$rv[0] = $code->($pointer, @_);
				}
				&Net::SSLeay::Error::die_if_ssl_error($method);
				wantarray ? @rv : $rv[0];
			};
		};
	}
	if ( my $table = delete $ready{$caller} ) {
		while ( my ($method, $code) = each %$table ) {
			my $fullname = $caller."::".$method;
			next if defined &{$fullname};
			print STDERR "installing $method into $caller\n"
				if $caller =~ /ErrorZZ/;
			*{$fullname} = $install->($code, $method);
		}
	}
};

1;

__END__

=head1 NAME

Net::SSLeay::Functions - convert Net::SSLeay functions to methods

=head1 SYNOPSIS

 use Net::SSLeay::Functions 'foo';

 # means, roughly:
 use Net::SSLeay::Functions sub {
         my $code = shift;
         sub {
             my $self = shift;
             $code->($self->foo, @_);
         }
     };

=head1 DESCRIPTION

This internal utility module distributes Net::SSLeay functions into
the calling package.  Its import method takes a callback which should
return a callback to be assigned into the symbol table; not providing
that will mean that the Net::SSLeay function is directly assigned into
the symbol table of the calling namespace.

If a function is passed instead of a closure, it is taken to be the
name of an attribute which refers to where the Net::SSLeay magic
pointer is kept.

The difference between the version of the installed handler function
and the actual installed function is that the real one checks for
OpenSSL errors which were raised while the function was called.

=cut

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
