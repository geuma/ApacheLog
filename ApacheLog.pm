package ApacheLog;
#
# ApacheLog - a Collectd Plugin
# Copyright (C) 2010-2011 Stefan Heumader <stefan@heumader.at>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#

use strict;
use warnings;

use Fcntl qw (:flock);

use Collectd qw( :all );

#
# configure the plugin
#

my $config =
{
	LogFile => '/var/log/apache2/access.log', # path to the access log file of apache
	TmpFile => '/tmp/collectd-apachelog.tmp', # path for the temporary file of this plugin
	Domains => [
		'www.urandom.at',
		'www.pdlna.com',
	], # anonymous array for domains, which should be evaluated
		# TODO: configuration should be done by using another technique like using a seperate
		# config file or getting the params from the collectd configuration file
};

#
# plugin code itself
#  touch it at your own risk
#

our $VERSION = '0.16';

my $dataset =
[
	{
		name => 'hits',
		type => Collectd::DS_TYPE_GAUGE,
		min => 0,
		max => 65535,
	},
	{
		name => 'bytes',
		type => Collectd::DS_TYPE_GAUGE,
		min => 0,
		max => 65535,
	},
];

sub ApacheLog_init
{
	return 1;
}

sub write_tmpfile
{
	my $last_log_line = shift;

	if (open(TMPFILE, ">".$config->{'TmpFile'}))
	{
		flock(TMPFILE, LOCK_EX);
		print TMPFILE $last_log_line;
		flock(TMPFILE, LOCK_UN);
		close(TMPFILE);
		return 1;
	}
	else
	{
		Collectd::plugin_log(Collectd::LOG_ERR, "Cannot open $config->{'TmpFile'} for writing.");
	}
	return 0;
}

sub read_tmpfile
{
	if (-e $config->{'TmpFile'})
	{
		open(TMPFILE, $config->{'TmpFile'}) || return "";
		my $last_log_line = <TMPFILE>;
		close(TMPFILE);
		return $last_log_line;
	}
	return "";
}

sub ApacheLog_read
{
	my $lastline = read_tmpfile();
	open(FILE, $config->{'LogFile'});
	my @lines = <FILE>;
	close(FILE);
	write_tmpfile($lines[-1]);

	# splicing already evaluated lines from logfile
	my $index = 0;
	for (my $i = 0; $i < scalar @lines; $i++)
	{
		if ($lines[$i] eq $lastline)
		{
			$index = $i;
			last;
		}
	}
	$index++;
	splice(@lines, 0, $index);

	# initializing all stats with zeros
	my %domains = ();
	foreach my $domain (@{$config->{'Domains'}})
	{
		$domains{$domain}->{'hits'} = 0;
		$domains{$domain}->{'bytes'} = 0;
	}

	foreach (@lines)
	{
		# TODO use an intelligent log file parser or write one on your own
		# current logfile configuration, which is supported with our mechanism
		# CustomLog /var/log/apache2/access.log "%v %h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-agent}i\""
		my ($domain, $client_ip, undef, undef, $time, $timezone, $requesttype, $requesturl, $protocol, $status_code, $bytes, $referer, $useragent) = split(' ', $_);
		if (defined($domains{$domain}))
		{
			$domains{$domain}->{'hits'}++;
			$domains{$domain}->{'bytes'} += $bytes if defined($bytes);
		}
	}
	foreach my $domain (keys %domains)
	{
		my $vl = {};
		$vl->{'values'} = [ $domains{$domain}->{'hits'}, $domains{$domain}->{'bytes'}, ];
		$vl->{'plugin'} = 'ApacheLog';
		Collectd::plugin_dispatch_values($domain, $vl);
	}

	return 1;
}

sub ApacheLog_write
{
	my $type = shift;
	my $ds = shift;
	my $vl = shift;

	if (scalar (@$ds) != scalar (@{$vl->{'values'}})) {
		Collectd::plugin_log (Collectd::LOG_ERR, "DS number does not match values length");
		return;
	}
	for (my $i = 0; $i < scalar (@$ds); ++$i) {
		print "$vl->{'host'}: $vl->{'plugin'}: ";
		if (defined $vl->{'plugin_instance'}) {
			print "$vl->{'plugin_instance'}: ";
		}
		print "$type: ";
		if (defined $vl->{'type_instance'}) {
			print "$vl->{'type_instance'}: ";
		}
		print "$vl->{'values'}->[$i]\n";
	}
	if (scalar (@$ds) != scalar (@{$vl->{'values'}}))
	{
		Collectd::plugin_log(Collectd::LOG_WARNING, "DS number does not match values length");
		return;
	}

	return 1;
}

sub ApacheLog_log
{
	return 1;
}

sub ApacheLog_shutdown
{
	return 1;
}

foreach my $domain (@{$config->{'Domains'}})
{
	Collectd::plugin_register(Collectd::TYPE_DATASET, $domain, $dataset);
}
#Collectd::plugin_register(Collectd::TYPE_CONFIG, "ApacheLog", $config);
Collectd::plugin_register(Collectd::TYPE_INIT, "ApacheLog", \&ApacheLog_init);
Collectd::plugin_register(Collectd::TYPE_READ, "ApacheLog", "ApacheLog_read");
Collectd::plugin_register(Collectd::TYPE_WRITE, "ApacheLog", "ApacheLog_write");
Collectd::plugin_register(Collectd::TYPE_LOG, "ApacheLog", "ApacheLog_log");
Collectd::plugin_register(Collectd::TYPE_SHUTDOWN, "ApacheLog", "ApacheLog_shutdown");

1;
