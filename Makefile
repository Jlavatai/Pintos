CLEAN_SUBDIRS = src doc tests

all::
	make -C src

clean::
	for d in $(CLEAN_SUBDIRS); do $(MAKE) -C $$d $@; done

distclean:: clean
	find . -name '*~' -exec rm '{}' \;

check::
	make -C tests $@
