#!perl -T
use 5.014;
use strict;
use warnings FATAL => 'all';
use Test::More;

plan tests => 1;

BEGIN {
    use_ok( 'MinD::Mail::Spamfilter' ) || print "Bail out!\n";
}
