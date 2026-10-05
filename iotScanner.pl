use strict;
use warnings;
use AnyEvent::HTTP;
use Data::Dumper;
use MIME::Base64;
use Digest::SHA;
use JSON;

#   Options:
#     devCfgUrl=<url>        Load device config from URL
#     cfgFile=<path>         Load device config from file (default: devices.cfg)
#     ports=<p1,p2,...>      Override port list (default: from config + 80,443,8080)
#     concurrency=<n>        Parallel connections (default: 10)
#     timeout=<sec>          HTTP timeout per request (default: 10)
#     output=<text|json|csv> Output format (default: text)
#     debug[=level]          Debug output
#     -h                     Show this help

my $devs = {};
my @ipList = ();
my $ptr = -1;
my $debug = 0;
my $concurrency = 10;
my $httpTimeout = 10;
my $outputFormat = "text";
my $devCfgUrl = "";
my $cfgFile = "devices.cfg";
my @results = ();       # for json/csv output
my @globalPorts = ();   # ports to scan per IP (assembled from config + defaults)

if (!defined $ARGV[0] || $ARGV[0] =~ /^\-?h/) {
    print "perl iotScanner.pl <ipRanges> [options]\n";
    print "  ipRanges:  10.0.0.1-10.0.0.254 or 10.0.0.1,10.0.0.2\n";
    print "  Options:\n";
    print "    devCfgUrl=<url>        Load device config from URL\n";
    print "    cfgFile=<path>         Config file path (default: devices.cfg)\n";
    print "    ports=<p1,p2,...>      Override port list\n";
    print "    concurrency=<n>        Parallel connections (default: 10)\n";
    print "    timeout=<sec>          HTTP timeout in seconds (default: 10)\n";
    print "    output=<text|json|csv> Output format (default: text)\n";
    print "    debug[=level]          Enable debug output\n";
    exit;
}

# Parse arguments
for (my $i = 1; $i <= $#ARGV; $i++) {
    if ($ARGV[$i] =~ /^devCfgUrl=(.+)/) {
        $devCfgUrl = $1;
    } elsif ($ARGV[$i] =~ /^cfgFile=(.+)/) {
        $cfgFile = $1;
    } elsif ($ARGV[$i] =~ /^ports=(.+)/) {
        @globalPorts = split(/,/, $1);
    } elsif ($ARGV[$i] =~ /^concurrency=(\d+)/) {
        $concurrency = $1;
    } elsif ($ARGV[$i] =~ /^timeout=(\d+)/) {
        $httpTimeout = $1;
    } elsif ($ARGV[$i] =~ /^output=(text|json|csv)/) {
        $outputFormat = $1;
    } elsif ($ARGV[$i] =~ /^debug/) {
        if ($ARGV[$i] =~ /=(\d+)/) {
            $debug = $1;
        } else {
            $debug = 1;
        }
        print STDERR "debug=$debug\n";
    }
}

readDevices();
buildPortList();

# Build IP list from ranges
foreach my $e (split(/\,/, $ARGV[0])) {
    if ($e =~ /^(.+?)\-(.+)$/) {
        my $start = $1;
        my $end   = $2;
        if ($debug) { print STDERR "range: $start -> $end\n"; }
        for (my $i = ip2num($start); $i <= ip2num($end); $i++) {
            push @ipList, num2ip($i);
        }
    } else {
        push @ipList, $e;
    }
}

# Each IP gets scanned on all ports, so expand the work queue
my @workQueue = ();
foreach my $ip (@ipList) {
    foreach my $port (@globalPorts) {
        push @workQueue, { ip => $ip, port => $port };
    }
}

my $numOfJobs = scalar @workQueue;
my $numOfResults = 0;

if ($numOfJobs == 0) {
    print STDERR "No targets to scan.\n";
    exit 1;
}

if ($debug) { print STDERR "Scanning " . scalar(@ipList) . " IPs x " . scalar(@globalPorts) . " ports = $numOfJobs jobs, concurrency=$concurrency, timeout=${httpTimeout}s\n"; }

if ($outputFormat eq "csv") {
    print "ip,port,device_type,status,detail\n";
}

my $w = AnyEvent->condvar;

for (my $i = 0; $i < $concurrency; $i++) {
    kickoff();
}

$w->recv;

# Print JSON results at end
if ($outputFormat eq "json") {
    print encode_json(\@results) . "\n";
}

# Core functions

sub kickoff {
    $ptr++;
    if (!defined $workQueue[$ptr]) { return; }
    my $job = $workQueue[$ptr];
    check({ ip => $job->{ip}, port => $job->{port}, stage => "" });
}

sub finish_job {
    $numOfResults++;
    if ($numOfResults >= $numOfJobs) {
        # Use a small timer to let the event loop flush, then exit
        my $t; $t = AnyEvent->timer(after => 0.1, cb => sub { undef $t; exit; });
    } else {
        kickoff();
    }
}

sub report_result {
    my ($ip, $port, $devType, $status, $detail) = @_;
    if ($outputFormat eq "text") {
        print "device $ip:$port is of type $devType $detail\n";
    } elsif ($outputFormat eq "csv") {
        # Escape commas in fields
        $devType =~ s/,/;/g;
        $detail  =~ s/,/;/g;
        print "$ip,$port,$devType,$status,$detail\n";
    } elsif ($outputFormat eq "json") {
        push @results, {
            ip       => $ip,
            port     => $port,
            devType  => $devType,
            status   => $status,
            detail   => $detail,
        };
    }
}

sub composeURL {
    my $ctx = shift;
    my $port = $ctx->{port} || 80;
    my $scheme = ($port == 443 || $port == 8443 || $port == 4443) ? "https" : "http";
    my $portStr = "";
    if (($scheme eq "http" && $port != 80) || ($scheme eq "https" && $port != 443)) {
        $portStr = ":$port";
    }
    if (!defined $ctx->{url}) {
        return "$scheme://$ctx->{ip}$portStr/";
    } elsif ($ctx->{url} =~ /^https?:/) {
        return $ctx->{url};
    } elsif ($ctx->{url} =~ /^\//) {
        return "$scheme://$ctx->{ip}$portStr$ctx->{url}";
    } else {
        print STDERR "unexpected partial url $ctx->{url}\n";
        return "$scheme://$ctx->{ip}$portStr/$ctx->{url}";
    }
}

sub search4devType {
    my ($body_ref, $headers_ref) = @_;
    foreach my $e (keys %{$devs}) {
        my $d = $devs->{$e};
        next unless defined $d->{devTypePattern};

        my $p = $d->{devTypePattern};
        my $tmp;

        if ($p->[0]->[0] eq "header") {
            # AnyEvent::HTTP lowercases header names
            $tmp = $headers_ref->{lc($p->[0]->[1])};
            next unless defined $tmp;
        } elsif ($p->[0]->[0] eq "body") {
            if ($p->[0]->[1] eq "") {
                $tmp = $$body_ref;
            } else {
                my $tag = $p->[0]->[1];
                # case insensitive tag extraction
                my $pattern = "<$tag>(.*?)</$tag>";
                if ($$body_ref =~ /$pattern/si) {
                    $tmp = $1;
                } else {
                    next;
                }
            }
        } else {
            next;
        }

        next unless defined $tmp;

        my $matcher = $p->[1];
        my $mtype = $matcher->[0];
        my $len = scalar @{$matcher};

        if ($mtype eq "==") {
            if ($tmp eq $matcher->[1]) {
                return $e;
            }
        } elsif ($mtype =~ /^regex/) {
            my $matched = 1;
            for (my $i = 1; $i < $len; $i++) {
                my $pat = $matcher->[$i];
                if ($tmp !~ /$pat/) {
                    $matched = 0;
                    last;
                }
            }
            return $e if $matched;
        } elsif ($mtype eq "substr") {
            if (index($tmp, $matcher->[1]) >= 0) {
                return $e;
            }
        }
    }
    return "";
}

sub check_login {
    my $ctx = shift;
    my $url = composeURL($ctx);
    my $dev = $ctx->{dev};
    my $body_text = $ctx->{body} || "";

    if ($dev->{auth}->[0] eq "basic") {
        if ($dev->{auth}->[1] eq "") {
            # just test if 200 comes back
            http_get $url, timeout => $httpTimeout, tls_ctx => "low", sub {
                my $status = $_[1]->{Status};
                if ($status == 200) {
                    report_result($ctx->{ip}, $ctx->{port}, $ctx->{devType}, "DEFAULT_CREDS", "still has default password (no-auth)");
                } else {
                    report_result($ctx->{ip}, $ctx->{port}, $ctx->{devType}, "CHANGED", "has changed password");
                }
                finish_job();
            };
            return;
        }
        my $auth_header = "Basic " . encode_base64($dev->{auth}->[1], "");
        if ($debug) { print STDERR "checking basic login on $url\n"; }
        http_get $url, timeout => $httpTimeout, tls_ctx => "low",
            headers => { Authorization => $auth_header }, sub {
            my $status = $_[1]->{Status};
            if ($debug) { print STDERR "check_login status=$status for $url\n"; }
            if ($status == 200 || $status == 301 || $status == 302) {
                report_result($ctx->{ip}, $ctx->{port}, $ctx->{devType}, "DEFAULT_CREDS", "still has default password");
            } elsif ($status == 401) {
                report_result($ctx->{ip}, $ctx->{port}, $ctx->{devType}, "CHANGED", "has changed password");
            } else {
                report_result($ctx->{ip}, $ctx->{port}, $ctx->{devType}, "UNKNOWN", "unexpected resp code $status");
            }
            finish_job();
        };
    } elsif ($dev->{auth}->[0] eq "form") {
        my $subtype  = $dev->{auth}->[1];
        my $postdata = $dev->{auth}->[2];

        # Extract form data if needed
        if (defined $dev->{extractFormData}) {
            foreach my $pattern (@{$dev->{extractFormData}}) {
                if ($body_text =~ /$pattern/) {
                    if (!defined $ctx->{extractedData}) { $ctx->{extractedData} = []; }
                    push @{$ctx->{extractedData}}, $1;
                }
            }
        }
        if ($subtype =~ /^sub/) {
            $postdata = substitute($postdata, $ctx->{extractedData});
        }

        if ($debug) { print STDERR "checking form login on $url with: $postdata\n"; }
        http_post $url, $postdata, timeout => $httpTimeout, tls_ctx => "low", sub {
            my $resp_body = $_[0];
            my $status    = $_[1]->{Status};
            if ($debug) { print STDERR "form login status=$status\n"; }

            if (scalar @{$dev->{auth}} >= 6 && $dev->{auth}->[3] eq "body") {
                my $check_type  = $dev->{auth}->[4];
                my $check_value = $dev->{auth}->[5];
                my $is_default  = 0;

                if ($check_type eq "regex") {
                    $is_default = ($resp_body =~ /$check_value/) ? 1 : 0;
                } elsif ($check_type eq "substr") {
                    $is_default = (index($resp_body, $check_value) >= 0) ? 1 : 0;
                } elsif ($check_type eq "!substr") {
                    $is_default = (index($resp_body, $check_value) < 0) ? 1 : 0;
                }

                if ($is_default) {
                    report_result($ctx->{ip}, $ctx->{port}, $ctx->{devType}, "DEFAULT_CREDS", "still has default password");
                } else {
                    report_result($ctx->{ip}, $ctx->{port}, $ctx->{devType}, "CHANGED", "has changed password");
                }
            } else {
                report_result($ctx->{ip}, $ctx->{port}, $ctx->{devType}, "UNKNOWN", "form auth response status=$status (no body check configured)");
            }
            finish_job();
        };
        return;
    } elsif ($dev->{auth}->[0] eq "expect200") {
        if ($debug) { print STDERR "checking expect200 on $url\n"; }
        http_get $url, timeout => $httpTimeout, tls_ctx => "low", sub {
            my $status = $_[1]->{Status};
            if ($status == 200) {
                report_result($ctx->{ip}, $ctx->{port}, $ctx->{devType}, "NO_AUTH", "does not have any password");
            } else {
                report_result($ctx->{ip}, $ctx->{port}, $ctx->{devType}, "PROTECTED", "endpoint returned $status");
            }
            finish_job();
        };
        return;
    } else {
        report_result($ctx->{ip}, $ctx->{port}, $ctx->{devType}, "SKIP", "unknown auth type: $dev->{auth}->[0]");
        finish_job();
    }
}

sub proceed_to_login {
    my ($ctx, $body_ref) = @_;
    my $dev = $ctx->{dev};
    $ctx->{body} = $$body_ref;

    if (defined $dev->{loginUrlPattern}) {
        my $pattern = $dev->{loginUrlPattern};
        if ($$body_ref =~ /$pattern/) {
            $ctx->{url} = $1;
            return check_login($ctx);
        }
    }

    if (defined $dev->{nextUrl}) {
        my $nu = $dev->{nextUrl};
        if ($nu->[0] eq "string" && $nu->[1] ne "") {
            $ctx->{url} = $nu->[1];
        }
    }
    check_login($ctx);
}

sub check {
    my $ctx = shift;
    my $url = composeURL($ctx);

    if ($debug) { print STDERR "checking $url\n"; }

    http_get $url, timeout => $httpTimeout, tls_ctx => "low", sub {
        my ($body, $hdr) = @_;
        my $status = $hdr->{Status};

        if ($debug) { print STDERR "got status=$status for $url\n"; }

        # Handle TCP connection failure
        if ($status == 595 || $status =~ /^59/) {
            if ($debug) { print STDERR "device $ctx->{ip}:$ctx->{port}: connection failed (status $status)\n"; }
            finish_job();
            return;
        }

        # Handle redirects (follow up to 5)
        if (($status == 301 || $status == 302) && (!defined $ctx->{redirects} || $ctx->{redirects} < 5)) {
            if (defined $hdr->{location}) {
                if ($debug) { print STDERR "http redirect to $hdr->{location}\n"; }
                $ctx->{url} = $hdr->{location};
                $ctx->{redirects} = ($ctx->{redirects} || 0) + 1;
                return check($ctx);
            }
        }

        if ($status == 401) {
            my $devType = search4devType(\$body, $hdr);
            if ($devType eq "") {
                if ($debug) { print STDERR "$ctx->{ip}:$ctx->{port}: 401 but no device type matched\n"; }
                finish_job();
                return;
            }
            if ($debug) { print STDERR "devType=$devType (401)\n"; }
            $ctx->{devType} = $devType;
            $ctx->{url}     = $url;
            $ctx->{dev}     = $devs->{$devType};
            $ctx->{body}    = $body;
            return check_login($ctx);

        } elsif ($status == 200) {
            my $devType = search4devType(\$body, $hdr);
            if ($devType ne "") {
                if ($debug) { print STDERR "devType=$devType (200)\n"; }
                $ctx->{dev}     = $devs->{$devType};
                $ctx->{devType} = $devType;
                return proceed_to_login($ctx, \$body);
            }

            # try META refresh URL
            if ($ctx->{stage} eq "") {
                my $refreshUrl = getRefreshUrl(\$body, $ctx->{url});
                if ($refreshUrl ne "") {
                    $ctx->{url}   = $refreshUrl;
                    $ctx->{stage} = "look4LoginPage";
                    return check($ctx);
                }
            }

            # Still no match after refresh
            if ($debug) { print STDERR "$ctx->{ip}:$ctx->{port}: 200 but no device type matched\n"; }
            finish_job();
            return;

        } elsif ($status == 404) {
            if ($debug) { print STDERR "$ctx->{ip}:$ctx->{port}: got 404\n"; }
            finish_job();
            return;
        } else {
            if ($debug) { print STDERR "$ctx->{ip}:$ctx->{port}: unexpected status $status\n"; }
            finish_job();
            return;
        }
    };
}

sub getRefreshUrl {
    my ($body_ref, $prevUrl) = @_;
    my $newUrl = "";
    my $tmpBody = $$body_ref;
    while ($tmpBody =~ /\<META\s+[^\>]*url=(.*?)>/i) {
        $tmpBody = $';
        my $tmp = $1;
        if ($tmp =~ /^[\"\'](.*?)[\"\']/) {
            $newUrl = $1; last;
        } elsif ($tmp =~ /^(.*?)[\>\"\s]/) {
            $newUrl = $1; last;
        }
    }
    if ($newUrl ne "" && $newUrl ne $prevUrl) {
        return $newUrl;
    }
    return "";
}

sub readDevices {
    my $buff;
    if ($devCfgUrl ne "") {
        require LWP::UserAgent;
        require HTTP::Request;
        my $ua = LWP::UserAgent->new;
        $ua->agent('Mozilla/5.0');
        $ua->ssl_opts(verify_hostname => 0, SSL_verify_mode => 0x00);
        my $req = HTTP::Request->new('GET', $devCfgUrl);
        my $res = $ua->request($req);
        $buff = $res->content;
    } else {
        open(my $fh, '<', $cfgFile) or die "Failed to open $cfgFile: $!\n";
        local $/;
        $buff = <$fh>;
        close $fh;
    }
    $devs = decode_json($buff);

    foreach my $k (keys %{$devs}) {
        if (ref($devs->{$k}) ne "HASH") {
            delete $devs->{$k};
        }
    }

    my $count = scalar keys %{$devs};
    if ($debug) { print STDERR "Loaded $count device definitions from $cfgFile\n"; }
}

sub buildPortList {
    # If specified ports on CLI, use those only
    if (scalar @globalPorts > 0) {
        if ($debug) { print STDERR "Using CLI ports: " . join(",", @globalPorts) . "\n"; }
        return;
    }

    my %portSet;
    # Always include these
    $portSet{80}  = 1;
    $portSet{443} = 1;
    $portSet{8080} = 1;

    foreach my $k (keys %{$devs}) {
        my $d = $devs->{$k};
        if (defined $d->{ports} && ref($d->{ports}) eq "ARRAY") {
            foreach my $p (@{$d->{ports}}) {
                $portSet{$p} = 1;
            }
        }
    }
    @globalPorts = sort { $a <=> $b } keys %portSet;
    if ($debug) { print STDERR "Scanning ports: " . join(",", @globalPorts) . "\n"; }
}

sub substitute {
    my ($str, $p) = @_;
    my $ret = "";
    while ($str =~ /\$(\d+)/) {
        $ret .= $` . ($p->[$1 - 1] // "");
        $str = $';
    }
    $ret .= $str;
    return $ret;
}

sub ip2num {
    my @a = split(/\./, $_[0]);
    return ($a[0] << 24) + ($a[1] << 16) + ($a[2] << 8) + $a[3];
}

sub num2ip {
    my $n = shift;
    return sprintf("%d.%d.%d.%d", ($n >> 24), ($n >> 16) & 0xff, ($n >> 8) & 0xff, $n & 0xff);
}

__END__