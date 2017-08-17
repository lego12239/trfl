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
		$self->{_soap} = SOAP::Lite->new(proxy => $p{soap_uri},
		  ns => $p{soap_ns});
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
	my $resp;
	my $soap = $self->{_soap};


	syslog(LOG_INFO, "send a request");
	eval {
		$resp = $soap->call("sendRequest",
		  SOAP::Data->name("requestFile" => $self->{_req})->type("base64Binary"),
		  SOAP::Data->name("signatureFile" => $self->{_sig})->type("base64Binary"),
		  SOAP::Data->name("dumpFormatVersion" => "2.2")->type("string"));
	};
	if ($@) {
		die("rknr_req: soap exception: ".$@);
	}
	if ($resp->fault()) {
		die("soap error: ".$resp->faultcode().": ".$resp->faultstring().
		  "(".$resp->faultdetail().")");
	}
	$resp = $resp->body()->{sendRequestResponse};
	if (!defined($resp)) {
		die("response is empty!");
	}
	if ($resp->{result} ne 'true') {
		die("rknr_req: soap error: ".$resp->{resultComment});
	}
	syslog(LOG_INFO, "request is sent(".$resp->{code}.")");

	return $resp->{code};
}

sub get_result
{
	my $self = shift;
	my ($code) = @_;
	my $ret = 0;
	my $ret_msg = "";
	my $resp;
	my $soap = $self->{_soap};
	my $iter = 0;
	my $delay = 20;


	syslog(LOG_INFO, "get a result");

	sleep(90);
	while ($ret == 0) {
		syslog(LOG_INFO, ($iter+1)." try...");
		
		eval {
			$resp = $soap->call("getResult",
			  SOAP::Data->name("code" => $code));
		};
		if ($@) {
			die("rknr_req: soap exception: ".$@);
		}
		if ($resp->fault()) {
			die("soap error: ".$resp->faultcode().": ".$resp->faultstring().
			  "(".$resp->faultdetail().")");
		}
		$resp = $resp->body()->{getResultResponse};
		if (!defined($resp)) {
			die("response is empty!");
		}
		if ($resp->{result} eq "true") {
			$ret = $resp->{resultCode};
		} elsif ($resp->{result} eq "false") {
			$ret = $resp->{resultCode};
			$ret_msg = $resp->{resultComment};
		}
		$iter++;
		if ($iter > 100) {
			$ret = "too_many_retries";
			last;
		}

		$delay += 5;
		$delay = 25 if ($delay > 300);
		sleep($delay);
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
	
	return decode_base64($resp->{registerZipArchive});
}

sub get_data
{
	my $self = shift;
	my $code;


	$code = $self->send_req();
	return $self->get_result($code);
}

sub get_info
{
	my $self = shift;
	my $soap = $self->{_soap};
	my $resp;
	
	syslog(LOG_INFO, "get a last dump time...");
	eval {
		$resp = $soap->call("getLastDumpDateEx");
	};
	if ($@) {
		die("rknr_req: soap exception: ".$@);
	}
	if ($resp->fault()) {
		die("soap error: ".$resp->faultcode().": ".$resp->faultstring().
		  "(".$resp->faultdetail().")");
	}
	$resp = $resp->body()->{getLastDumpDateExResponse};
	if (!defined($resp)) {
		die("response is empty!");
	}
	return {
		ut_reg => $resp->{lastDumpDate},
		ut_urgent => $resp->{lastDumpDateUrgently},
		ver_docs => $resp->{docVersion},
		ver_regfmt => $resp->{dumpFormatVersion},
		ver_api => $resp->{webServiceVersion}};
}

1;
