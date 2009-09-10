
package Net::SSLeay::Error;

use Net::SSLeay;
use Moose;

has 'err' =>
	isa => 'Int',
	is => 'ro',
	required => 1,
	default => sub {
		Net::SSLeay::ERR_get_error;
	};
	;

sub ssl_error_pending {
	Net::SSLeay::ERR_peek_error;
}

has 'error_code' =>
	isa => "Int",
	is => "ro",
	;

has 'library_name' =>
	isa => "Str",
	is => "ro",
	;

has 'function_name' =>
	isa => "Str",
	is => "ro",
	;

has 'reason_string' =>
	isa => "Str",
	is => "ro",
	;

has 'next' =>
	isa => __PACKAGE__,
	is => "ro",
	;

sub BUILD {
	my $self = shift;
	my $ssl_error = $self->error_string;
	(undef, my @fields) = split ":", $ssl_error, 5;
	$self->{error_code} ||= hex(shift @fields);
	$self->{library_name} ||= shift @fields;
	$self->{function_name} ||= shift @fields;
	$self->{reason_string} ||= shift @fields;

	# OpenSSL throws an entire stack backtrace, so capture all the
	# outstanding SSL errors and chain them off this one.
	if ( ssl_error_pending ) {
		$self->{next} = (ref $self)->new(message => "next error");
	}
}

has 'message' =>
	isa => "Str",
	is => "rw",
	;

sub die_if_ssl_error {
	my $message = shift;
	if ( ssl_error_pending ) {
		die __PACKAGE__->new(message => $message);
	}
}

sub as_string {
	my $self = shift;
	my $message = $self->message;
	if ( $message ) {
		unless ( $message =~ / / ) {
			$message = "During `$message'";
		}
		$message .= ": ";
	}
	else {
		$message = "";
	}
	my $reason_string = $self->reason_string;
	my $result = do {
		if ( $reason_string eq "system lib" ) { # FIXME: lang
			sprintf("%s%.8x: trace: %s (%s)",
				$message, $self->error_code,
				$self->function_name, $self->library_name);
		}
		else {
			sprintf("%sOpenSSL error 0x%.8x: %s during %s (%s)",
				$message,
				$self->error_code,
				$self->reason_string,
				$self->function_name, $self->library_name)
				.($self->next ?
					  "\n".$self->next->as_string
						  : "");
		}
	};
	if ( $result =~ m{\n} and $result !~ m{\n\Z} ) {
		$result .= "\n";
	}
	$result;
}

use overload
	'""' => \&as_string,
	;

use Sub::Exporter -setup => {
	exports => [ qw(die_if_ssl_error ssl_error_pending) ],
};

use Net::SSLeay::Functions sub {
	my $code = shift;
	sub {
		my $self = shift;
		$code->($self->err, @_);
	}
};

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
