#!/usr/bin/perl -w
# eDirACL2AD.pl - convert Novell edirectory ACLs to AD dsacls calls


## define used packages ##
use Getopt::Long;
use Net::LDAP::LDIF;
use Net::LDAP::Entry;


## declare functions ##
sub error($@);
sub usage($);


## initialize global variables ##
my $progname = $0;
   $progname =~ s#.*/(.*?)$#$1#  if ($^O =~ /(?:[iu]x\b|solaris)/i);
   $progname =~ s#.*\\(.*?)$#$1#  if ($^O !~ /(?:[iu]x\b|solaris)/i);
my $version = '0.3';

# option variables #
my %opt;
my @optionNames = (
  'q|quiet',
  'H|help',
  'V|version',
# 'config|C=s@'			# reserved for Getopt::rcFile
);


##### main() function #####

  # get options #
  Getopt::Long::Configure('bundling', 'require_order', 'no_ignore_case');
  GetOptions(\%opt, @optionNames)  or  usage(1);

  # option check #
  usage(0)  if ($opt{H});
  if ($opt{V}) {
    print STDERR $progname . ' version ' . $version . "\n";
    exit(0);
  }

  # check number of arguments #
  usage(1)  if (($#ARGV < 0) || ($#ARGV > 0));

  # do the work #
  my $ ldif = Net::LDAP::LDIF->new($ARGV[0], 'r')
    or die $?;

  while (defined(my $e = $ldif->read_entry)) {
    my $dn = $e->dn;
    my @acls = $e->get_value('ACL');

    foreach my $acl (@acls) {
      if ($acl =~/^(.+)#(.+)#(.+)#(.+)$/) {
        my ($perms,$scope,$user,$attr) = ($1,$2,$3,$4);
        my $ADperms = '';
        my $ADflags = '';

        if ($attr =~/\[Entry Rights\]$/i) {
          $attr = '';

          # object permissions
          $ADperms .= 'LO'  if ($perms & 1);	# browse
          $ADperms .= 'CC'  if ($perms & 2);	# create
          $ADperms .= 'SD'  if ($perms & 4);	# delete
          $ADperms .= ''  if ($perms & 8);	# rename
          $ADperms .= ''  if ($perms & 16);	# supervisor
        }
        else {
          $attr = ''  if ($attr =~/\[All Attributes Rights\]$/i);

          # attribute permissions
          $ADperms .= ''  if ($perms &  1);	# compare
          $ADperms .= 'RP'  if ($perms &  2);	# read
          $ADperms .= 'WP'  if ($perms &  4);	# write
          $ADperms .= 'WS'  if ($perms &  8);	# add self
          $ADperms .= ''  if ($perms & 32);	# supervisor (?)
        }

        my @dsacls = ('dsacls',
                      '"\\\\localhost:389\\'.$dn.'"',
                      ($scope =~ /subtree/) ? '/I:T' : '',
                      '/G',
                      '"'.$user.':'.$ADperms.';'.$attr.';"');

        print join(' ', @dsacls)."\n";
      }
    }
  }

  $ldif->done;

exit(0);



##### function definitions #####

## print out error message and eventually exit ##
# Synopsis:  error($status, $message)
sub error($@)
{
my $status = shift;
my @msg = @_;

  if (! $opt{q}) {
    print STDERR $progname . ": " . join(" ", @msg) . "\n";
  }

  if ($status) {
    exit($status);
  }
}


## print out usage message and exit ##
# Synopsis:  usage($status)
sub usage($)
{
my $status = shift;

  print STDERR "Usage: $progname [<options>] ...\n";

  if (! $status) {
    print STDERR "  where <options> are\n" .
                 "    -q  --quiet                silent operation (no error messages)\n" . 
                 "    -H  --help                 show this help page\n" . 
                 "    -V  --version              display version number\n"; 
  }  
  else {
    print STDERR "For help, type: $progname --help\n";
  }
  exit($status);
}

# EOF
