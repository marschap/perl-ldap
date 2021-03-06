#!/usr/local/bin/perl
#
#----------------------------------------------------------------------------
#
# This program was written by Clif Harden.
# It is uses the PERL LDAP, Tk, and Tk::JPEG modules.
# These modules are available from the PERL CPAN
# system.
#
# $Id: jpegDisplay.pl,v 1.2 2003/06/18 18:23:31 gbarr Exp $
#
# Purpose: This program is designed to retrieve jpeg photo data
#          from an LDAP directory.
#
#
# Revisions:
# $Log: jpegDisplay.pl,v $
# Revision 1.2  2003/06/18 18:23:31  gbarr
# Remove all references to :all as it is not recommended
#
# Revision 1.1  2001/03/12 14:01:46  gbarr
# New contrib scripts from Clif Harden
#
#
#
#

use Getopt::Std;
use Net::LDAP;
use Net::LDAP::Filter;
use Tk;
use Tk::JPEG;

#
# Initialize opt hash.
# You can change the defaults to match your setup.
# This can eliminate the need for many of the input
# options on the command line.
#
my %opt = (
  b => 'dc=harden,dc=org',
  h => 'localhost',
  d => 0,
  D => 'cn=manager',
  w => 'password',
  V => 3,
  a => 'cn',
  v => 'commonName'
);

if (@ARGV == 0) {
#
# print usage message.
#
  Usage();
}

#
# Get command line options.
#

getopts('b:h:d:D:w:V:a:v:Z',\%opt);

#
# build filter string
#
my $match = "( $opt{a}=$opt{v}  )";

my $jpegFile = "./$opt{a}=$opt{v}.jpg";

#
# create filter object
#
my $filter = Net::LDAP::Filter->new($match)
  or die "Bad filter '$match'";

#
# make ldap connection to directory.
#
my $ldap = new Net::LDAP($opt{h},
                         timeout => 10,
                         debug => $opt{d},
                         version => $opt{V})
  or die $@;

#
# call start_tls
#
if ($opt{Z}) {
  $ldap->start_tls();
}

#
# Bind to directory.
#
my $mesg = $ldap->bind($opt{D}, password => "$opt{w}");
die $mesg->error,$mesg->code
  if $mesg->code;

#
# Search directory for record that matches filter
#
$mesg = $ldap->search(base   => $opt{b},
                      filter => $filter,
                      attrs  => ['jpegPhoto']);
die $mesg->error,$mesg->code
  if $mesg->code;

#
# get record entry object
#
$entry = $mesg->entry();

if ( !defined($entry) ) {
  print "\n";
  print "No data for filter $match.\n" if ($mesg->count == 0) ;
  print "\n";
}
else {
  my @attrs = sort $entry->attributes;
  my $max = 0;

  $dn = $entry->dn();

  my @pictures = $entry->get_value('jpegPhoto');
  if(@pictures) {
    $picture = $pictures[0];
  }
  else {
    print "\n";
    print "No jpegPhoto attribute for DN\n";
    print "$dn\n";
    print "\n";
    $ldap->unbind;
    exit;
  }
}

#
# Store the jpeg data to a temp file.
#
open(TMP, "+>$jpegFile");
binmode(TMP);
$| = 1;

print TMP $picture;
close(TMP);

if ( !-e "$jpegFile" ) {
  print "\n";
  print "Could not create temporary jpeg file $jpegFile\n";
  print "\n";
  $ldap->unbind;
  exit(1);
}

$ldap->unbind;

#
# Create a TK window to display the jpeg picture.
#
my $mw  = MainWindow->new();

my $list = $mw->Listbox(-height => 1, -width => length($dn));
$list->pack(-side => 'top');
$list->insert('end', $dn);
my $image = $mw->Photo(-file => $jpegFile, -format => 'jpeg');

print "\n";
print "Displaying jpegPhoto for\n";
print "$dn\n";
print "\n";

$mw->Label(-image => $image)->pack(-expand => 1, -fill => 'both');
$mw->Button(-text => 'Quit', -command => [destroy => $mw])->pack;
MainLoop;

unlink $jpegFile;

#----------------------------------------#
# Usage() - display simple usage message #
#----------------------------------------#
sub Usage
{
  print( "Usage: [-Z] [-b <base>] [-h <host>] [-d <number>] [-D <DN>] [-w <password>] [-a <attribute>] [-v <data>]\n" );
  print( "\t-b    Search base.\n" );
  print( "\t-d    Debug mode.  Display debug messages to stdout.\n" );
  print( "\t-D    Authentication Distinguished Name.\n" );
  print( "\t-h    LDAP directory host computer.\n" );
  print( "\t-w    Authentication password.\n" );
  print( "\t-a    Attribute that will be incorporated into the search filter.\n" );
  print( "\t-v    Data that will be incorporated into the search filter.\n" );
  print( "\t-V    LDAP version of the LDAP directory.\n" );
  print( "\t-Z    start SSL encryption using start_tls.\n" );
  print( "\n" );
  print( "\t      Perldoc pod documentation is included in this script.\n" );
  print( "\t      To read the pod documentation do the following;\n" );
  print( "\t      perldoc <script name>\n" );
  print( "\n" );
  print( "\n" );
  exit( 1 );
}

__END__

=head1 NAME

jpegDisplay.pl  -  A script to display a jpeg picture from jpegPhoto attribute of an LDAP directory entry.

=head1 SYNOPSIS

The intent of this script is to show the user how to retrieve and
display a jpeg photo from an LDAP directory entry.

This script has been tested on OpenLDAP 2.0.7 & 2.4.39 directory servers
and a Netscape 4.x LDAP directory server.

You may need to change the first line of the Perl jpegDisplay.pl script
to point to your file pathname of perl.

=head1 Input options.

 -b    Search base.
 -d    Debug mode.  Display debug messages to stdout.
 -D    Distinguished Name for authentication purposes.
 -h    LDAP directory host computer.
 -w    Authentication password.
 -a    Attribute that will be incorporated into the search filter.
 -v    Data that will be incorporated into the search filter.
 -V    LDAP version of the LDAP directory.
 -Z    start SSL encryption using start_tls

 Usage: jpegDisplay.pl -b <base> -h <host> -d <number> -D <DN> \
                    -w <password> -a <attribute> -v <data>

Inside the script is a opt hash that can be initialized to
default values that can eliminate the need for many of the
input options on the command line.

-------------------------------------------------------------------

=head1 REQUIREMENTS

To use this program you will need the following.

At least PERL version 5.004.  You can get a stable version of PERL
from the following URL;
   http://cpan.org/src/index.html

Perl LDAP module.  You can get this from the following URL;
   ftp://ftp.duke.edu/pub/CPAN/modules/by-module/Net/

Perl Tk.800.22 module.  You can get this from the following URL;
   ftp://ftp.duke.edu/pub/CPAN/modules/by-module/Net/

Perl Tk-JPEG-2.014 module.  You can get this from the following URL;
   ftp://ftp.duke.edu/pub/CPAN/modules/by-module/Net/

Bundled inside each PERL module is instructions on how to install the
module into your PERL system.

-------------------------------------------------------------------

=head1 INSTALLING THE SCRIPT

Install the jpegDisplay.pl script anywhere you wish, I suggest
/usr/local/bin/jpegDisplay.pl.

-------------------------------------------------------------------

Since the script is in PERL, feel free to modify it if it does not
meet your needs.  This is one of the main reasons I did it in PERL.
If you make an addition to the code that you feel other individuals
could use let me know about it.  I may incorporate your code
into my code.

=head1 AUTHOR

Clif Harden <charden@pobox.com>
If you find any errors in the code please let me know at
charden@pobox.com.

=head1 COPYRIGHT

Copyright (c) 2001 Clif Harden. All rights reserved. This program is
free software; you can redistribute it and/or modify it under the same
terms as Perl itself.

=cut

