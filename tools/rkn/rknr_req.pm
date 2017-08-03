package rknr_req;

use strict;
use MIME::Base64;
use SOAP::Lite;
use Sys::Syslog qw(:standard :macros);
use Data::Dumper;

sub new
{
    my $class = shift;
    my %p = @_;
    my $self = {};
    my $ret;


    bless($self,$class);

    $self->_read_req($p{req});
    $self->_read_sig($p{sig});
	eval {
		$self->{_soap} = SOAP::Lite->service($p{wsdl});
	};
	if ($@) {
		die("rknr_req: soap exception: ".$@);
	}

err:
    return $self;
}

sub _read_file
{
	my $self = shift;
	my ($fname) = @_;
	my $fh;
	my $line;
	my $var = "";


	unless (open($fh, "<", $fname)) {
		die("rknr_req: file read error: $fname: $!");
	}

	while (defined($line = <$fh>)) {
		$var .= $line;
	}
	close($fh);
	return $var;
}

sub _read_req
{
    my $self = shift;
    my ($fname) = @_;


    $self->{_req} = $self->_read_file($fname);
}

sub _read_sig
{
    my $self = shift;
    my ($fname) = @_;


    $self->{_sig} = $self->_read_file($fname);
}

sub send_req
{
	my $self = shift;
	my @resp;
	my $soap = $self->{_soap};


	syslog(LOG_INFO, "send a request");
	eval {
		@resp = $soap->sendRequest($self->{_req}, $self->{_sig}, "2.0");
	};
	if ($@) {
		die("rknr_req: soap exception: ".$@);
	}

	if ($resp[0] ne 'true') {
		die("rknr_req: soap error: ".$resp[1]);
	}
	syslog(LOG_INFO, "request is sent(".$resp[2].")");

	return $resp[2];
}

sub get_result
{
	my $self = shift;
	my ($code) = @_;
	my $ret = 0;
	my $ret_msg = "";
	my @resp;
	my $soap = $self->{_soap};
	my $empty_cnt = 0;
	my $iter = 0;
	my $delay = 0;


	syslog(LOG_INFO, "get a result");

	while ($ret == 0) {
		syslog(LOG_INFO, ($iter+1)." try...");
		
		$delay += 60;
		$delay = 60 if ($delay > 300);
		sleep($delay);
		
		@resp = $soap->getResult($code);
		if (!@resp) {
			syslog(LOG_ERR, "response is empty!");
			$empty_cnt++;
			if ($empty_cnt > 2) {
				$ret = "too_many_empty";
				last;
			}
		}
		if ($resp[0] eq "true") {
			$ret = $resp[2];
		} elsif ($resp[0] eq "false") {
			$ret = $resp[2];
			$ret_msg = $resp[1];
		}
		$iter++;
		if ($iter > 100) {
			$ret = "too_many_retries";
			last;
		}
	}
	if ($ret != 1) {
		if ($ret eq "too_many_empty") {
			die("rknr_req: result getting error: too many empty responses");
		} elsif ($ret eq "too_many_retries") {
			die("rknr_req: result getting error: too many retries");
		} else {
			die("rknr_req: result getting error: $ret_msg");
		}
	}
	syslog(LOG_INFO, "result is got(on $iter iteration)");
	
	return decode_base64($resp[1]);
}

sub get_data
{
	my $self = shift;
	my $code;


	$code = $self->send_req();
	return $self->get_result($code);
}

1;
