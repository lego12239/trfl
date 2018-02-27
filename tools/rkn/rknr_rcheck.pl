#!/usr/bin/perl -I. -W

use strict;
use rknr_xmlp;
use Getopt::Long qw(:config gnu_getopt no_ignore_case);
use URI;
use URI::_idna;
use Cwd;
use Text::CSV;
use utf8;
use Data::Dumper;


my $data = {};
my @files;
my @ftimes;
my $opt_verbose = 0;
my $opt_rdetails = 0;
my $opt_details = 0;
my $opt_hidefalse = 0;


sub report_err
{
	my ($msg) = @_;


	print(STDERR "error: ".$msg."\n");
}

sub output_help
{
	print("Usage: rknr_rcheck.pl [OPTIONS] REVIZOR_REPORT ".
	  "REGISTRIES_PREFIXES\n\n".
	  "Options:\n".
	  " -h, --help            show help\n".
	  " -V, --version         show program version\n".
	  " -v, --verbose         show progress info\n".
	  " -h, --hide-false      hide false fails\n".
	  " -s, --show-rdetails   show revizor failure details\n".
	  " -S, --show-details    show register entry details\n".
	  "REVIZOR_REPORT         csv report file\n".
	  "REGISTRIES_PREFIXES    files prefixes separated with space\n".
	  "                       e.g. for backup/dump all backup/dump* will be ".
	  "used\n");
}

sub output_version
{
	print("rknr_rcheck.pl 0-2.0\n");
}

sub proc_opts
{
	my ($opt_h, $opt_V, $opt_v);

	GetOptions('help|h' => \$opt_h,
	  'version|V' => \$opt_V,
	  'verbose|v' => \$opt_verbose,
	  'hide-false' => \$opt_hidefalse,
	  'show-rdetails|s' => \$opt_rdetails,
	  'show-details|S' => \$opt_details);

	if ( $opt_h ) {
		output_help();
		exit(0);
	}
	
	if ($opt_V) {
		output_version();
		exit(0);
	}
}

sub info_out
{
	my ($fmt) = shift(@_);
	
	return unless ($opt_verbose);
	printf($fmt."\n", @_);
}

sub reset_data_counters
{
	my $id;
	my @ids;
	
	@ids = keys(%$data);
	foreach $id (@ids) {
		$data->{$id}{found} = 0;
	}
	
}

sub load_rdata
{
	my ($file) = @_;
	my $fh;
	my $csv;
	my $row;
	my $is_body = -1;
	
	if ((!defined($file)) || ($file eq "")) {
		die("REVIZOR_REPORT isn't specified");
	}
	unless (open($fh, "<:encoding(cp1251)", $file)) {
		die("$file open error: $!");
	}
	$csv = Text::CSV->new({binary => 1, sep_char => ";", decode_utf8 => 1});
	if (!$csv) {
		die("$file: can't create csv instance");
	}
	# omit a header
	while (defined($row = $csv->getline($fh))) {
		$is_body++ if (($row->[0] eq "") || ($is_body >= 0));
		last if ($is_body == 2);
	}
	if ($csv->eof()) {
		return;
	}
	if ((0 + $csv->error_diag())) {
		die("$file: ".$csv->error_diag());
	}
	# read a body
	while (defined($row = $csv->getline($fh))) {
		if (!defined($data->{$row->[4]})) {
			$data->{$row->[4]} = {
				rchecks => [],
				regs => []};
		}
		
		push(@{$data->{$row->[4]}{rchecks}}, {
			time => $row->[0],
			node => $row->[1],
			node_addr => $row->[2],
			node_coord => $row->[3],
			id => $row->[4],
			req => $row->[5],
			id_org => $row->[6],
			id_time => $row->[7],
			http_code => $row->[8],
			http_redir => $row->[9]});
	}
	if (((0 + $csv->error_diag()) != 2012) &&
	    ((0 + $csv->error_diag()) != 0)) {
		die("$file: ".(0 + $csv->error_diag()));
	}
	close($fh);
}

sub get_files_list
{
	my $pref;
	my @files;
	my @sorted;
	
	foreach $pref (@_) {
		push(@files, glob($pref."*"));
	}
	@sorted = sort(@files);
	
	return @sorted;
}

sub analyze_prepare
{
	my $i;
	
	push(@ftimes, @files);
	foreach $i (@ftimes) {
		$i =~ s/^.*(\d{4}-\d{2}-\d{2}T\d{2}:\d{2})$/$1/o;
	}
}

sub collect_info
{
	my $file;
	my $id;
	my @ids;
	my $info;
	my $xmlp;
	
	info_out("collect info");
	@ids = keys(%$data);
	foreach $file (@_) {
		next unless (-f $file);
		reset_data_counters();
		foreach $id (@ids) {
			$info = {
				file => {
					name => $file,
					exist => 0},
				entry => undef};					
			push(@{$data->{$id}{regs}}, $info);
		}
		$xmlp = new rknr_xmlp(file => $file,
		  cb => {"/reg:register/content" => sub {
		    return _proc_entry(\@ids, @_)}});
		$xmlp->xml_parse();

		info_out("%s is read", $file);
	}
}

sub _proc_entry
{
	my ($ids, $entry) = @_;
	my $id;
	my $info;
	
	foreach $id (@$ids) {
		next if ($data->{$id}{found});
		if ($id eq $entry->{__ATTRS}{id}) {
			$data->{$id}{found} = 1;
			$info = $data->{$id}{regs}[$#{$data->{$id}{regs}}];
			$info->{file}{exist} = 1;
			$info->{entry} = clone_entry($entry);
		}
	}
	
	return 1;
}

sub clone_entry
{
	my ($entry) = @_;
	my $e = {};
	my @keys;
	my $i;
	
	@keys = keys(%{$entry->{__ATTRS}});
	foreach $i (@keys) {
		$e->{__ATTRS}{$i} = $entry->{__ATTRS}{$i};
	}

	@keys = keys(%{$entry->{decision}[0]{__ATTRS}});
	foreach $i (@keys) {
		$e->{decision}[0]{__ATTRS}{$i} = $entry->{decision}[0]{__ATTRS}{$i};
	}

	if (defined($entry->{url})) {
		$e->{url} = _clone_entry_fields($entry->{url});
	}

	if (defined($entry->{domain})) {
		$e->{domain} = _clone_entry_fields($entry->{domain});
	}

	if (defined($entry->{ip})) {
		$e->{ip} = _clone_entry_fields($entry->{ip});
	}

	if (defined($entry->{ipSubnet})) {
		$e->{ipSubnet} = _clone_entry_fields($entry->{ipSubnet});
	}
	
	return $e;
}

sub _clone_entry_fields
{
	my ($f) = @_;
	my $i;
	my $ret = [];
	
	foreach $i (@$f) {
		push(@$ret, {__TEXT => $i->{__TEXT}});
	}
	
	return $ret;
}

sub show_info
{
	my @ids;
	my $id;
	my $i;
	my $f;
	
	@ids = keys(%$data);
	foreach $id (@ids) {
		analyze($data->{$id});
		if ($opt_hidefalse) {
			$f = 1;
			for $i (@{$data->{$id}{rchecks}}) {
				$f = 0 if (!$i->{_is_false});
			}
			next if ($f);
		}
		printf("%s\n", $id);
		foreach $i (@{$data->{$id}{etl}}) {
			printf("  %s  %s:%s\n", $i->{time}, $i->{type},
			  join(",", @{$i->{flags}}));
			if ($opt_verbose) {
				printf("    %s\n", $i->{title});
			}
			if (($opt_rdetails) && ($i->{type} eq "c")) {
				printf("    %s (%s, %s)\n", $i->{e}{req}, $i->{e}{http_code},
				  $i->{e}{http_redir});
			}
			if (($opt_details) && ($i->{type} eq "r")) {
				show_entry($i->{e}{entry});
			}
		}
		printf("\n\n");
	}
}

sub analyze
{
	my ($dentry) = @_;
	my @states; # 0 - INITIAL, 1 - ABSENT, 2 - PRESENT, 3 - CHECK_FAIL
	my $state;
	my $e;
	my $t;
	my $i;
	my $j;
	
	for($i = 0; $i <= $#ftimes; $i++) {
		$dentry->{etl}[$i] = {
			title => $dentry->{regs}[$i]{file}{name},
			time => $ftimes[$i],
			type => "r",
			e => $dentry->{regs}[$i],
			flags => [$dentry->{regs}[$i]{file}{exist} ? "PRESENT" :
			  "absent"]};
	}
	foreach $i (@{$dentry->{rchecks}}) {
		$i->{_is_false} = 0;
		$t = _rtime2iso($i->{time});
		@states = (0);
		for($j = 0; $j <= $#ftimes; $j++) {
			if ($dentry->{regs}[$j]{file}{exist}) {
				$state = 2;
			} else {
				$state = 1;
			}
			if ($states[0] != $state) {
				# use reverse order just for simplicity
				unshift(@states, $state);
			}
			if ($ftimes[$j] le $t) {
				if ($j == $#ftimes) {
					unshift(@states, 3);
				} elsif ($ftimes[$j+1] gt $t) {
					unshift(@states, 3);
				}
			}
		}
		$e = {
			title => $i->{time},
			time => $t,
			type => "c",
			e => $i,
			flags => ["fail"]};
		$state = join(",", reverse(@states));
		if (($state eq "0,2,3,1") ||
		    ($state eq "0,2,1,3,1") ||
		    ($state eq "0,2,1,3")) {
			push(@{$e->{flags}}, "FALSE");
			$i->{_is_false} = 1;
		}
		push(@{$dentry->{etl}}, $e);
	}
	
	@states = sort {$a->{time} cmp $b->{time}} @{$dentry->{etl}};
	$dentry->{etl} = [@states];
}

sub _rtime2iso
{
	my ($rtime) = @_;
	my %mon = ("Янв" => "01", "Фев" => "02", "Мар" => "03", "Апр" => "04",
	  "Май" => "05", "Июн" => "06", "Июл" => "07", "Авг" => "08",
	  "Сен" => "09", "Окт" => "10", "Ноя" => "11", "Дек" => "12");
	
	if ($rtime !~ /^(\d{2})\s+(\S{3}),\s+(\d{4})\s+(\d{2}):(\d{2}):\d{2}$/o) {
		die("rtime2iso: date time format error: $rtime");
	}
	return $3."-".$mon{$2}."-".$1."T".$4.":".$5;
}

sub show_entry
{
	my ($entry) = @_;
	my @keys;
	my $i;
	
	@keys = keys(%{$entry->{__ATTRS}});
	foreach $i (@keys) {
		printf("    %s=%s\n", $i, $entry->{__ATTRS}{$i}); 
	}

	print("    decision: ");
	@keys = keys(%{$entry->{decision}[0]{__ATTRS}});
	foreach $i (@keys) {
		printf("%s=%s ", $i, $entry->{decision}[0]{__ATTRS}{$i}); 
	}
	print("\n");

	if (defined($entry->{url})) {
		print("    url:\n");
		_show_entry_fields($entry->{url});
	}

	if (defined($entry->{domain})) {
		print("    domain:\n");
		_show_entry_fields($entry->{domain});
	}

	if (defined($entry->{ip})) {
		print("    ip:\n");
		_show_entry_fields($entry->{ip});
	}

	if (defined($entry->{ipSubnet})) {
		print("    ipSubnet:\n");
		_show_entry_fields($entry->{ipSubnet});
	}
}

sub _show_entry_fields
{
	my ($f) = @_;
	my $i;
	
	foreach $i (@$f) {
		printf("      %s\n", $i->{__TEXT});
	}
}


######################################################################
# MAIN
######################################################################

binmode(STDOUT, ":utf8");

proc_opts();

load_rdata(shift(@ARGV));
exit(0) unless (%$data);
@files = get_files_list(@ARGV);
analyze_prepare(@files);
collect_info(@files);
show_info();
