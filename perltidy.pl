#!/usr/bin/perl -w
#
#  perltidy.pl - apply or test for whitespace rules using Perl::Tidy
#
# Copyright (C) 2009  NZ Registry Services
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the Artistic License 2.0 or later.  You should
# have received a copy of the Artistic License the file COPYING.txt.
# If not, see <http://www.perlfoundation.org/artistic_license_2_0>

use Perl::Tidy;
use File::Find;
use Getopt::Long qw(:config bundling);
use FindBin qw($Bin);

my $test_only;
my $perltidyrc = "$Bin/.perltidyrc";
my @dirs;
my $files_regex = qr{\.(pm|t|PL|pl)$};

GetOptions(
	"test|t"        => \$test_only,
	"rc=s"          => \$perltidyrc,
	"include|I=s\@" => \@dirs,
	"files|f=s"     => \$files_regex,
);

if ( !@dirs ) {
	@dirs = qw(lib t);
}

my @files;
if (@ARGV) {
	@files = @ARGV;
}
else {
	find(   sub {
			if ( $_ eq "examples" ) {
				$File::Find::prune = 1;
			}
			elsif (m{$files_regex}) {
				push @files, $File::Find::name;
			}
		},
		"lib",
		"t"
	);
}

my $seen_untidy = 0;

for my $file (@files) {
	local (@ARGV);
	my @tidy_opts;
	if ( -f $perltidyrc ) {
		push @tidy_opts, perltidyrc => $perltidyrc;
	}
	else {
		push @tidy_opts, argv => "--perl-best-practices";
	}
	Perl::Tidy::perltidy(
		source      => $file,
		destination => "$file.tidy",
		@tidy_opts,
	);

	my $rc = system("diff -q $file $file.tidy >/dev/null");
	if ( !$rc ) {
		unlink("$file.tidy");
	}
	elsif ($test_only) {
		print "$file is UNTIDY\n";
		unlink("$file.tidy");
		$seen_untidy++;
	}
	else {
		print "$file was changed\n";
		rename( "$file.tidy", $file );
	}
}

exit $seen_untidy;

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
