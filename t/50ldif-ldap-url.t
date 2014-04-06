#!perl

use Test::More;
use Net::LDAP::LDIF;
use Net::LDAP::Entry;

BEGIN { require "t/common.pl" }


start_server()
? plan tests => 15
: plan skip_all => 'no server';


$ldap = client();
ok($ldap, "client");

$mesg = $ldap->bind($MANAGERDN, password => $PASSWD);

ok(!$mesg->code, "bind: " . $mesg->code . ": " . $mesg->error);

ok(ldif_populate($ldap, "data/41-in.ldif"), "data/41-in.ldif");

$ldap->unbind()

# now search the database

my $ldifdata = <<'LDIF';
dn: cn=All Staff Members,ou=Groups,o=University of Michigan,c=US
member:< ldap://localhost:9009/o=University%20of%20Michigan,c=US?1.1?sub?(objectclass=person)

LDIF

open(my $ldifhandle, '<', \$ldifdata);

my $ldif = Net::LDAP::LDIF->new($ldifhandle);
isa_ok($ldif, Net::LDAP::LDIF, "object");

my $entry = $ldif->read_entry;
isa_ok($entry, Net::LDAP::Entry, "entry");

# TODO:
# - check for # of args (compared to previous read)
# - use a 2nd entry that fetches attributes
# - use a 3rd entry that fails fetching data

print STDERR $entry->dump;

