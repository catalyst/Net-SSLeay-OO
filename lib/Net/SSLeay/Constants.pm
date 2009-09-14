
package Net::SSLeay::Constants;

use strict;
use warnings;

use Net::SSLeay;

=head1 NAME

Net::SSLeay::Constants - Importer interface to Net::SSLeay constants

=head1 SYNOPSIS

 use Net::SSLeay::Constants qw(OP_ALL);

 print OP_ALL;

=head1 DESCRIPTION

This module allows L<Net::SSLeay> constants to be explicitly imported
into your program.

As well as avoiding using the verbose C<&Net::SSLeay::XXXX> syntax all
the time, they can then be spelt as bare words.  It also means that
instead of waiting for run-time for your misspelt Net::SSLeay
constants to crash your program, you find out at compile time.

=cut

our $VERSION = "0.01";

sub import {
	my $class = shift;
	my $target = caller;
	while ( my $thingy = shift ) {
		if ( $thingy =~ m{^\d+} ) {
			no warnings "numeric";
			die "insufficient version $thingy"
				if 0+$thingy < 0+$VERSION;
		}
		else {
			no strict 'refs';
			my $val = eval { &{"Net::SSLeay::$thingy"}() };
			if ( defined $val ) {
				*{$target."::".$thingy} = sub() { $val };
			}
			else {
				die "tried to import '$thingy', but SSLeay said: $@";
			}
		}
	}
}

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