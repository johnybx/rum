#!/usr/bin/perl -w

use strict;
use Fcntl qw(:flock);
use Getopt::Long;
use Data::Dumper;
use CDB_File;
use DBI;

my $cdb_file="/etc/rum/mysql50.cdb.tmp";
my $cdb_file_tmp="/etc/rum/mysql50.cdb.tmp.$$";
my $cdb_file_final="/etc/rum/mysql50.cdb";

my %servers=('mysql1:3306','mysql2:3306','mysql3:3306');
my $db_user='root';
my $db_pass='password';


umask 0077;

# quit if other export script is already running
open SELF, "< $0" or die "cant open myself\n";
flock SELF, LOCK_EX | LOCK_NB  or exit;

my $with_root_from;

# --with-root-from=mysql1:3306
my $result=GetOptions ("with-root-from=s" => \$with_root_from);

my %data;

foreach my $server (%servers) {
	my $dbh = DBI->connect("dbi:mysql:mysql:host=$server",$db_user,$db_pass) or die "Unable to connect to database: ", DBI->errstr;
	my $dbq=$dbh->prepare("SELECT user,password FROM user WHERE user!='zabbix'");
	$dbq->execute();
	if ($dbq->rows<=0) {
		error("query failed from server $server");
	}

	while (my $tmp= $dbq->fetchrow_hashref()) {
		if (${$tmp}{'user'} eq 'root') {
			if (!(defined($with_root_from) && $with_root_from eq $server)) {
				next;
			}
		}

		if (defined($data{${$tmp}{'user'}})) {
			print "duplicate user on 2 servers. user: ${$tmp}{'user'} ($server ".$data{${$tmp}{'user'}}{'server'}.")\n";
		}
		$data{${$tmp}{'user'}}{'password'}=${$tmp}{'password'};
		$data{${$tmp}{'user'}}{'server'}=$server;
	}

	if ($dbh->err) {
		error("Data fetching terminated early by error: ".$dbh->errstr);
	}

	$dbq->finish;

	$dbh->disconnect;
}

my $cdb = new CDB_File ($cdb_file, $cdb_file_tmp) or error("cant create cdb file $!");

foreach my $user (keys %data) {
	my $value=$data{$user}{'password'}."\0tcp:".$data{$user}{'server'}."\0";
	$cdb->insert($user, $value);
}

$cdb->finish or error("cdb->finish");

rename $cdb_file,$cdb_file_final or error("cannot rename $cdb_file to $cdb_file_final");

exit 0;

sub error {
        my ($msg) = @_;
        print STDERR "Fatal Error: $msg\n";
        if (-e $cdb_file_tmp) {
                unlink($cdb_file_tmp);
        }
        exit 1;
}

