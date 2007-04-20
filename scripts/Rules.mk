# This Makefile is used to automate the analysis of network management
# traces. It is currently pretty much SNMP specific but we envision to
# expand on other network management protocols in the future.
#
# $Id$

BASE		?= "needs-to-be-set"
SNMPBASE	= $(BASE)-snmp
ALLBASE		= $(BASE)-all

GROUP		= traces
MODE		= o-rx

# --- site specific definitions --

SNMPDUMP	= snmpdump
DOT		= twopi

SCRIPTS		= /home/schoenw/src/snmpdump/scripts
SNMPSTATS	= $(SCRIPTS)/snmpstats.pl
SNMPFLOWSTATS	= $(SCRIPTS)/snmpflowstats.pl
SNMPOIDSTATS	= $(SCRIPTS)/snmpoidstats.pl
MIBIDENTIFIERS	= $(SCRIPTS)/mib-identifiers.txt
FLOWSTAT2DOT	= $(SCRIPTS)/flowstat2dot.pl
SNMPSERIES	= $(SCRIPTS)/snmpseries.pl
SNMPWALKS	= $(SCRIPTS)/snmpwalks.pl

# --- snmp targets ---

all:	$(SNMPBASE).csv.gz $(SNMPBASE)-stats.txt $(SNMPBASE)-flowstats.txt $(SNMPBASE).pdf $(SNMPBASE)-walks.txt

$(SNMPBASE)-stats.txt: $(SNMPBASE).csv.gz
	perl $(SNMPSTATS) -n $(BASE) -f "" -O $(SNMPBASE)-stats.sql $< > $@

$(SNMPBASE)-flows: $(SNMPBASE).csv.gz
	-mkdir $(SNMPBASE)-flows
	zcat $< | $(SNMPDUMP) -i csv -o csv -F -C $(SNMPBASE)-flows -P $(BASE) \
		> $(SNMPBASE)-flows/$(BASE)-unknown.csv

$(SNMPBASE)-flowstats.txt: $(SNMPBASE)-flows
	perl $(SNMPFLOWSTATS) $(SNMPBASE)-flows/$(BASE)-*.csv* > $@

$(SNMPBASE)-oidstats.txt: $(SNMPBASE).csv
	perl $(SNMPOIDSTATS) -m $(MIBIDENTIFIERS) $< > $@

$(SNMPBASE).dot: $(SNMPBASE)-flowstats.txt
	perl $(FLOWSTAT2DOT) $< > $@

$(SNMPBASE).ps: $(SNMPBASE).dot
	$(DOT) -T ps $< > $@

$(SNMPBASE).pdf: $(SNMPBASE).ps
	epstopdf $<

$(SNMPBASE)-mpm.data: $(SNMPBASE)-flowstats.txt
	sort -n -r -k 5 $< | awk 'NF == 7 {printf("%d %f\n", NR, $$5);}' > $@

$(SNMPBASE)-bpm.data: $(SNMPBASE)-flowstats.txt
	sort -n -r -k 5 $< | awk 'NF == 7 {printf("%d %f\n", NR, $$6);}' > $@

$(SNMPBASE)-flows.ps: $(SNMPBASE)-mpm.data $(SNMPBASE)-bpm.data $(SNMPBASE)-flows.gp
	gnuplot $(SNMPBASE)-flows.gp > $@

$(SNMPBASE)-flows.pdf: $(SNMPBASE)-flows.ps
	epstopdf $<

$(SNMPBASE)-series.txt: $(SNMPBASE).csv.gz
	perl $(SNMPSERIES) $< > $@

$(SNMPBASE)-walks.txt: $(SNMPBASE).csv.gz
	perl $(SNMPWALKS) -n $(BASE) -f "" -O $(SNMPBASE)-walks.sql $< > $@

# --- maintenance targets ---

compress:
	gzip -r -9 .

uncompress:
	gunzip -r .

clean:

clobber: clean
	rm -rf flows

permissions:
	-chgrp -R $(GROUP) .
	-chmod -R $(MODE) .
