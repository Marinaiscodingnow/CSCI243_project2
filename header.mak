#
# standard compilation and link flags
#

CFLAGS = -ggdb -std=c99 -Wall -Wextra -pedantic

CLIBFLAGS = -lm

#
# TEST_MAIN is a unit test program that tests private library functions
#

TEST_MAIN = unit_test

#
# allall default overrides the standard all target to relink decode binary
#

allall:: all $(TEST_MAIN)
	@echo "\t'make allall' completed."
	@echo ""
	@echo "\tNOTE: you must make allclean before any 'gmakemake >Makefile'"

#
# allclean overrides realclean to remove unit test source
#

allclean: realclean
	#rm -f ./decode
	rm -f $(TEST_MAIN) $(TEST_MAIN).o $(TEST_MAIN).c

#
# because gmakemake tries to link the unit_test code with the library code,
# unit_test.ut file works around gmakemake shortcoming to create TEST_MAIN.
# test dependency must be hard-coded to the library because
# $(SOURCEFILES) is not yet defined in the Makefile.
#

$(TEST_MAIN).c:	 $(TEST_MAIN).ut
	cp $? $(TEST_MAIN).c

$(TEST_MAIN).o: cbc_lib.c

$(TEST_MAIN):  $(TEST_MAIN).o
	$(CC) $(CFLAGS) -o $@ $(TEST_MAIN).o $(CLIBFLAGS)

