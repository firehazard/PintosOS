# -*- perl -*-
use strict;
use warnings;
use tests::tests;

our ($test);
my (@output) = read_text_file ("$test.output");

common_checks (@output);

my ($thread_cnt) = 16;
my ($iter_cnt) = 16;
my (@order);
my (@t) = (-1) x $thread_cnt;

my (@iterations) = grep (/iteration:/, @output);
fail "No iterations found in output.\n" if !@iterations;

my (@numbering) = $iterations[0] =~ /(\d+)/g;
fail "First iteration does not list exactly $thread_cnt threads.\n"
  if @numbering != $thread_cnt;

my (@sorted_numbering) = sort { $a <=> $b } @numbering;
for my $i (0...$#sorted_numbering) {
    if ($sorted_numbering[$i] != $i) {
	fail "First iteration does not list all threads "
	  . "0...$#sorted_numbering\n";
    }
}

for my $i (1...$#iterations) {
    if ($iterations[$i] ne $iterations[0]) {
	fail "Iteration $i differs from iteration 0\n";
    }
}

fail "$iter_cnt iterations expected but " . scalar (@iterations)  . " found\n"
  if $iter_cnt != @iterations;

pass;
