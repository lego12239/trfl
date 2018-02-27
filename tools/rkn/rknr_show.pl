#!/usr/bin/perl -I. -W

use strict;
use rknr_xmlp;
use Getopt::Long qw(:config gnu_getopt);
use URI;
use URI::_idna;
use Cwd;
use Data::Dumper;


my $conf = {};
# conf optional parameters:
#   DOCVERSION_ONCHANGE
#   FORMATVERSION_ONCHANGE
#   APIVERSION_ONCHANGE
#
my $file;
my $act_hdlr;
my $xmlp;


sub report_err
{
	my ($msg) = @_;


	print(STDERR "error: ".$msg."\n");
}

sub output_help
{
	print("Usage: rknr_show.pl [OPTIONS] FILE MATCH_STATEMENT\n\n".
	  "Options:\n".
	  " -h, --help            show help\n".
	  " -v, --version         show program version\n".
	  "MATCH_STATEMENT:\n".
	  " head    show registry header\n".
	  " id ID   show entry with id=ID\n");
}

sub output_version
{
	print("rknr_show.pl 0-1.1\n");
}

sub proc_opts
{
	my ($opt_h, $opt_v);

	GetOptions('help|h' => \$opt_h,
	  'version|v' => \$opt_v);

	if ( $opt_h ) {
		output_help();
		exit(0);
	}
	
	if ($opt_v) {
		output_version();
		exit(0);
	}
}


sub _show_entry_fields
{
	my ($f) = @_;
	my $i;
	
	foreach $i (@$f) {
		printf("  %s\n", $i->{__TEXT});
	}
}

sub show_entry
{
	my ($entry) = @_;
	my @keys;
	my $i;
	
	@keys = keys(%{$entry->{__ATTRS}});
	foreach $i (@keys) {
		printf("  %s=%s\n", $i, $entry->{__ATTRS}{$i}); 
	}

	print("decision: ");
	@keys = keys(%{$entry->{decision}[0]{__ATTRS}});
	foreach $i (@keys) {
		printf("%s=%s ", $i, $entry->{decision}[0]{__ATTRS}{$i}); 
	}
	print("\n");

	if (defined($entry->{url})) {
		print("url:\n");
		_show_entry_fields($entry->{url});
	}

	if (defined($entry->{domain})) {
		print("domain:\n");
		_show_entry_fields($entry->{domain});
	}

	if (defined($entry->{ip})) {
		print("ip:\n");
		_show_entry_fields($entry->{ip});
	}

	if (defined($entry->{ipSubnet})) {
		print("ipSubnet:\n");
		_show_entry_fields($entry->{ipSubnet});
	}
}

sub show_head
{
	my ($file) = @_;
	my $xmlp;
	
	$xmlp = new rknr_xmlp(file => $file,
	  cb => {"/reg:register" => \&_show_head,
	    "/reg:register/content" => sub { return 1}});
	$xmlp->xml_parse();
}

sub _show_head
{
	my ($entry) = @_;
	my @keys;
	my $i;
	
	@keys = keys(%{$entry->{__ATTRS}});
	foreach $i (@keys) {
		printf("%s=%s\n", $i, $entry->{__ATTRS}{$i});
	}
	printf("\n");
	
	return 1;
}

sub show_by_id
{
	my ($file, $id) = @_;
	my $xmlp;

	$xmlp = new rknr_xmlp(file => $file,
	  cb => {"/reg:register/content" => sub {
	    return _show_by_id($id, @_)}});
	$xmlp->xml_parse();
}

sub _show_by_id
{
	my ($id, $entry) = @_;
	
	if ($entry->{__ATTRS}{id} eq $id) {
		show_entry($entry);
		return 2;
	}
	
	return 1;
}

sub get_file
{
	my ($file) = @_;
	
	if ((!defined($file)) || ($file eq "")) {
		die("FILE isn't specified");
	}
	return $file;
}

sub get_action
{
	my ($act) = @_;

	if (!defined($act)) {
		die("MATCH_STATEMENT isn't specified");
	} elsif ($act eq "head") {
		return \&show_head;
	} elsif ($act eq "id") {
		return \&show_by_id;
	}
	die("wrong MATCH_STATEMENT\n");
}


######################################################################
# MAIN
######################################################################

binmode(STDOUT, ":utf8");

proc_opts();

$file = get_file(shift(@ARGV));
$act_hdlr = get_action(shift(@ARGV));
&$act_hdlr($file, @ARGV);
