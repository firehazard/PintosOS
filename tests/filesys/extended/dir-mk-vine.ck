# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected (IGNORE_EXIT_CODES => 1, [<<'EOF']);
(dir-mk-vine) begin
(dir-mk-vine) mkdir "0"
(dir-mk-vine) chdir "0"
(dir-mk-vine) mkdir "1"
(dir-mk-vine) chdir "1"
(dir-mk-vine) mkdir "2"
(dir-mk-vine) chdir "2"
(dir-mk-vine) mkdir "3"
(dir-mk-vine) chdir "3"
(dir-mk-vine) mkdir "4"
(dir-mk-vine) chdir "4"
(dir-mk-vine) mkdir "5"
(dir-mk-vine) chdir "5"
(dir-mk-vine) mkdir "6"
(dir-mk-vine) chdir "6"
(dir-mk-vine) mkdir "7"
(dir-mk-vine) chdir "7"
(dir-mk-vine) mkdir "8"
(dir-mk-vine) chdir "8"
(dir-mk-vine) mkdir "9"
(dir-mk-vine) chdir "9"
(dir-mk-vine) create "test"
(dir-mk-vine) chdir "/"
(dir-mk-vine) open "/0/1/2/3/4/5/6/7/8/9/test"
(dir-mk-vine) end
EOF
