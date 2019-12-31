# Talkdesk Ranges

Talkdesk provides a soft-phone solution, Callbar, which relies on a few lists of hosts as defined on their website:

https://support.talkdesk.com/hc/en-us/articles/210173043-Quality-of-Service-QoS-Media-IP-ranges-for-traffic-shaping-at-your-firewall

https://support.talkdesk.com/hc/en-us/articles/204370859-Setting-up-System-Requirements-and-Network-Settings

One of these lists is fairly easy to parse, but the names are a little trickier. Amazon AWS, Cloudflare, and Google Cloud ranges must also be accounted for.

This tool aims to make it easier to deal with networking requirements where the soft phone traffic must be routed differently than the default traffic.

# Automation

Inside talkdesk_ranges.pl some urls and DNS records are defined:

```perl
# URLs with CIDR/name info
my $talkdesk_range_url  = "https://support.talkdesk.com/hc/en-us/articles/210173043-Quality-of-Service-QoS-Media-IP-ranges-for-traffic-shaping-at-your-firewall";
my $talkdesk_names_url  = "https://support.talkdesk.com/hc/en-us/articles/204370859-Setting-up-System-Requirements-and-Network-Settings";
my $aws_ip_url          = "https://ip-ranges.amazonaws.com/ip-ranges.json";
my $cloudflare_ip_url   = "https://www.cloudflare.com/ips-v4";
my $google_cloud_record = "_cloud-netblocks.googleusercontent.com";
```

This script reaches out to those pages and DNS servers as need be, parses the information, and returns a list of non-overlapping, non-duplicated CIDR ranges. Individual host IPs are returned as CIDR ranges as well (ie. 1.2.3.4/32).

This approach allows for fairly easily meeting routing requirements, if you don't mind having a huge routing table. An example can be found in example.sh.

# Requirements

This is a pure Perl program, so it could be ran under Linux/Max/Windows/etc, with the proper Perl modules installed (from your system repos, CPAN, etc).

It requires at least Perl v5.10 and a number of Perl modules to operate:

```perl
use File::Basename;                     # know where the script lives
use Getopt::Long;                       # handle arguments
use LWP::UserAgent;                     # www calls
use JSON::PP;                           # pure-perl JSON encoder/decoder
use NetAddr::IP;                        # range logic
use NetAddr::IP::Util
    qw(inet_ntoa ipv6_ntoa);            # binary to human readable
use Net::DNS::Dig;                      # get dns info based on names
```

# Usage

The help text is as follows:

```
  This program lists out ranges that could be associated with Talkdesk for Callbar software.
  These ranges include explicit Talkdesk resources, AWS, Cloudflare, and Google Compute Cloud ranges.

  Basic Usage: talkdesk_ranges.pl -s 'signifier' -a 'aws-range'

  Options:

    -s -signifier "string"
        Provide a signifier to use with name extrapolation, ie
        "corp", to pull IPs for corp.mytalkdesk.com and friends.

    -a -aws-range "string"
        Provide the AWS ranges to match against. Default is: us-east, us-west, GLOBAL
        Can be provided multiple times to return all the appropriate ranges.
        For example: us-east, eu-north, GLOBAL, etc.

    -n -nameserver "IP"
        Query a specific DNS nameserver instead of the default one.

    -t -tcp
        Do TCP based DNS lookups insted of UDP

    -4 
        Print IPv4 ranges (default)

    -6
        Print IPv6 ranges

    -h -help
        Summon a sentient, angry tuba.

  Examples:

    Generate a list of CIDR ranges for the talkdesk domain 'example'
      talkdesk_ranges.pl -s 'example'

    Get the list with a non-default set of AWS ranges:
      talkdesk_ranges.pl -s 'example' -a 'eu-north' -a 'GLOBAL'
```

# Bugs

The domain \*pusher.com (not \*.pusher.com) is listed as a wildcard domain in the Talkdesk domains, but currently not handled in the code.

If you find other bugs in the code, feel free open a bug/issue or fix the problem and open a PR.

