# SZARP SCADA
# Pawel Palucha pawel@praterm.com.pl

if MINGW32_OPT
INCLUDE_SUBDIRS = nagios
else
INCLUDE_SUBDIRS = nagios pserver-lite
endif

SUBDIRS = $(INCLUDE_SUBDIRS)

# Source directory
SOURCE_DIR=@srcdir@

# Additional files for deleting on 'make maintainer-clean'
MAINTAINERCLEANFILES = Makefile.in

# Compilations flags
AM_CPPFLAGS = \
		@XML_CFLAGS@ \
		@LUA_CFLAGS@ \
		@SSL_CFLAGS@ \
		@PTHREAD_CFLAGS@ \
		-I$(SOURCE_DIR)/../libSzarp/include \
		-I$(SOURCE_DIR)/../libSzarp2/include \
		-I$(SOURCE_DIR)/../include \
		-DPREFIX=\"@prefix@\" \
		-DINSTALL_PREFIX='"/opt/szarp"'

LIBSZARP=../libSzarp/libSzarp.la 
LIBSZARP2=../libSzarp2/libSzarp2.la ../libSzarp/libSzarp.la @BOOST_DATE_TIME_LIB@  @BOOST_THREAD_LIB@	@LUA_LIBS@

LDADD = @XML_LIBS@ $(LIBSZARP) @LUA_LIBS@

# Programs to create
if !MINGW32_OPT
bin_PROGRAMS = \
		@AGREGATOR@ \
		@ANALIZA2IPK@ \
		crypt \
		@IPK2SZARP@ \
		@IPKREP@ \
		@IPKMAX@ \
		lpparse \
		@PRECCONV@ \
		sproxy \
		vrsh \
		vrsh_d \
		analiza_create \
		@STAMPD@
	      
               
EXTRA_PROGRAMS = \
		analiza2ipk \
		agregator \
		ipk2szarp \
		ipkrep \
		ipkmax \
		precconv \
		analiza_create \
		stampd


EXTRA_DIST = \
              $(bin_SCRIPTS) \
              $(noinst_SCRIPTS) 

noinst_SCRIPTS = \
              isdn-up-in.sh \
              isdn-up-out.sh 
                 
bin_SCRIPTS = \
	      conf-get.sh \
	      conf-import.py \
	      conf-put.sh \
	      fdcp \
	      get_weather.sh \
	      i2smo \
              ipcclean \
              isdn-down.sh \
              isdn_pooler.sh \
              modem_pooler.sh \
              raprec \
	      raporter.py \
              rsync_wrap.pl \
	      sortlog \
              ssh_tunel.sh \
              szarp_scripter \
	      szarpinfo \
              szppp-off \
              szppp-on \
              szredialer \
	      szrsync \
	      szbpush \
	      probes_server/probes_client.py \
              remarks_server/remarks_server.py

endif

probesserverdir = @prefix@/lib/python
probesserver_PYTHON = \
	probes_server/libpar.py \
	probes_server/probes_server.py \
	probes_server/szbcache.py \
	probes_server/probes_server.tac

remarksserverdir = @prefix@/lib/python
remarksserver_PYTHON = \
	remarks_server/dbinteraction.py \
	remarks_server/paramssets.py \
	remarks_server/transdb.py \
	remarks_server/db.py \
	remarks_server/remarks.py \
	remarks_server/sessions.py


agregator_SOURCES = agregator.cc
agregator_LDADD = $(LIBSZARP2) $(LIBSZARP) @PTHREAD_CFLAGS@ @BOOST_SYSTEM_LIB@ @XML_LIBS@ @BOOST_LDFLAGS@ @BOOST_FILESYSTEM_LIB@ @BOOST_LOCALE_LIB@ @SSL_LIBS@

ipk2szarp_SOURCES = ipk2szarp.cc
ipk2szarp_LDADD = @PTHREAD_CFLAGS@ @XML_LIBS@ $(LIBSZARP2) $(LIBSZARP2) @BOOST_SYSTEM_LIB@ @BOOST_FILESYSTEM_LIB@ @BOOST_LOCALE_LIB@

lpparse_SOURCES = lpparse.cc
lpparse_LDADD = @PTHREAD_CFLAGS@ @XML_LIBS@ $(LIBSZARP)

ipkrep_SOURCES = ipkrep.cc
ipkrep_LDADD = @PTHREAD_CFLAGS@ @XML_LIBS@ @BOOST_SYSTEM_LIB@ $(LIBSZARP2) @BOOST_FILESYSTEM_LIB@ @BOOST_LOCALE_LIB@

precconv_SOURCES = precconv.cc
precconv_LDADD = $(LIBSZARP2) $(LIBSZARP) @PTHREAD_CFLAGS@ @XML_LIBS@ @BOOST_SYSTEM_LIB@ @BOOST_FILESYSTEM_LIB@ @BOOST_LOCALE_LIB@

analiza2ipk_SOURCES = analiza2ipk.cc
analiza2ipk_LDADD = @PTHREAD_CFLAGS@ @XML_LIBS@ $(LIBSZARP2) $(LIBSZARP) @BOOST_SYSTEM_LIB@ @BOOST_FILESYSTEM_LIB@ @BOOST_LOCALE_LIB@

ipkmax_SOURCES = ipkmax.cc
ipkmax_LDADD = @PTHREAD_CFLAGS@ @XML_LIBS@ $(LIBSZARP) $(LIBSZARP2) @BOOST_SYSTEM_LIB@ @BOOST_FILESYSTEM_LIB@ @BOOST_LOCALE_LIB@

crypt_LDADD = -lcrypt

vrsh_SOURCES = vrsh.c
vrsh_LDADD = $(LIBSZARP2) $(LIBSZARP) -lstdc++
vrsh_d_SOURCES = vrsh.c
vrsh_d_CPPFLAGS = -DDEBUG $(AM_CPPFLAGS)
vrsh_d_LDADD = $(LIBSZARP2) $(LIBSZARP) -lstdc++

analiza_create_SOURCES = analiza_create.c
analiza_create_CPPFLAGS = 
analiza_create_LDADD = 

stampd_SOURCES = stampd.c
stampd_LDADD = @EVENT_LIBS@ $(LIBSZARP)

