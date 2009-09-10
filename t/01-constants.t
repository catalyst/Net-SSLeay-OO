#!/usr/bin/perl -w

use strict;
use Test::More qw(no_plan);

BEGIN {
      use_ok("Net::SSLeay::Constants", "OP_ALL", "VERIFY_NONE",
             "VERIFY_PEER");
}

ok(&OP_ALL, "Imported OP_ALL");
cmp_ok(&VERIFY_PEER, '!=', &VERIFY_NONE, "Values are making some sense");

eval { Net::SSLeay::Constants->import("OP_YO_MOMMA") };
isnt($@, '', 'Trying to import bad symbol failed');

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
