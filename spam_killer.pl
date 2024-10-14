#!/usr/local/bin/perl

use strict;
use warnings;
use File::Tail;
use FileHandle;
use Time::HiRes;
use Net::Subnets;
use Getopt::Long;

use constant CVS_VERSION => scalar '$Revision: 1.11 $';

# Configurable globals
my $DEBUG = 3;
my $DEBUG_TO_SYSLOG = 0;
my $WHITE_LIST = "";
my $SYSLOG_MSGS_FILE = "/var/log/messages";
my $MAILER_IP = "";
my $MAILER_PORT = 25;
my $MAILER_SYSLOG_HOST = "mail1";
my $MAILER_SYSLOG_NAME = "sm-mta";
my $IPTABLES_CHAIN_NAME = "SPAM_UNAME_GUESSERS";

# Static variables
my $MY_MAX_RUNTIME = 3 * 24 * 60 * 60;
my $MAX_RUNTIME_SENDMAIL_CMD_WAIT = 15 * 60;
my $MAX_OFFENSES_BEFORE_FIREWALLED = 3;
my $MAX_BLOCKED_TIME = 60 * 60 * 3;
my $MAX_SYSLOG_READ_DELAY = 10;
my $FIND_EXE = "/usr/bin/find";
my $IPTABLES_EXE = "/usr/sbin/iptables";
my $LOGGER_EXE = "/usr/bin/logger";
my $IDLE_SLEEP_INTERVAL = 0;

# Periodic cleanup routines
my %PERIODIC_CLEANSERS = (
    'UnblockOldOffenders' => { 'frequency' => 10 * 60 },
    'KillSendmailsInCmdWait' => { 'frequency' => 10 * 60 },
);

# Log a "hello world" message
log_message(0, "Starting software, " . CVS_VERSION);
my $MY_START_TIME = time;

$| = 1;

# Parse the command-line options
parse_options();

# Initialize iptables rules/chain
initialize_iptables();

# Load the white-list; returns a Net::Subnets object
my $white_list = load_whitelist($WHITE_LIST);

# Open the syslog messages file using File::Tail
my $syslog = File::Tail->new(
    name       => $SYSLOG_MSGS_FILE,
    nowait     => 1,
    maxinterval => 90,
    adjustafter => 7,
    tail       => 100
);

my ($line, %OffendersPID, %OffendersIP);
MAIN_LOOP: while (1) {
    my $new_lines_matched = 0;

    # Process new log entries
    while (defined($line = $syslog->read) && length($line)) {
        $syslog->nowait(1);
        if ($line =~ /\b$MAILER_SYSLOG_HOST\b.+\b$MAILER_SYSLOG_NAME\Q[\E(\d+)\Q]\E: .+User unknown/) {
            $new_lines_matched++;
            my $pid = $1;
            $OffendersPID{$pid}{count}++;
            $OffendersPID{$pid}{last_offense} = time;
        }
    }

    # Handle idle state if no new lines are matched
    handle_idle_state($new_lines_matched, $syslog);

    # Process offending PIDs and extract offender IPs
    my @offending_pids = sort keys %OffendersPID;
    my $socket_inodes_per_pid = get_socket_inodes();
    my $proc_net_tcp = get_proc_net_tcp();

    foreach my $pid (@offending_pids) {
        process_offending_pid($pid, $socket_inodes_per_pid, $proc_net_tcp, \%OffendersPID, \%OffendersIP);
    }

    log_message(6, "Currently offending PIDs: " . join(", ", sort keys %OffendersPID));

    # Update offender IP data and apply firewall rules if necessary
    foreach my $rem_ip (sort { $OffendersIP{$a}{offenses} <=> $OffendersIP{$b}{offenses} } keys %OffendersIP) {
        handle_offender_ip($rem_ip, \%OffendersIP, $white_list);
    }

    # Perform periodic cleansers like unblocking old offenders
    run_periodic_cleanser('UnblockOldOffenders', \%OffendersIP);
    run_periodic_cleanser('KillSendmailsInCmdWait', $MAX_RUNTIME_SENDMAIL_CMD_WAIT);

    # Exit if max runtime is exceeded
    if ($MY_MAX_RUNTIME > 0 && (time - $MY_MAX_RUNTIME) > $MY_START_TIME) {
        log_message(0, "Exiting: Exceeded MAX_RUNTIME of $MY_MAX_RUNTIME secs");
        exit;
    }
} # End MAIN_LOOP

# Subroutine Definitions

sub handle_idle_state {
    my ($new_lines_matched, $syslog) = @_;
    if ($new_lines_matched < 1) {
        if ($IDLE_SLEEP_INTERVAL > 0) {
            log_message(6, "Sleeping.");
            Time::HiRes::sleep($IDLE_SLEEP_INTERVAL);
        } else {
            $syslog->nowait(0);
            log_message(6, "Going idle with syslog->nowait(0)");
        }
    }
}

sub run_periodic_cleanser {
    my ($cleanser, $args) = @_;
    my $last_run = $PERIODIC_CLEANSERS{$cleanser}{'lastrun'};
    my $frequency = $PERIODIC_CLEANSERS{$cleanser}{'frequency'};
    if ($last_run < (time - $frequency)) {
        $PERIODIC_CLEANSERS{$cleanser}{'lastrun'} = time;
        no strict 'refs';
        &{$cleanser}($args);
    }
}

sub process_offending_pid {
    my ($pid, $socket_inodes_per_pid, $proc_net_tcp, $OffendersPID, $OffendersIP) = @_;
    
    return unless $OffendersPID->{$pid}{count} > 0;
    log_message(4, "PID $pid has $OffendersPID->{$pid}{count} offenses");
    
    if (my $socket_inodes = $socket_inodes_per_pid->{$pid}) {
        foreach my $inode (@$socket_inodes) {
            if (my $tcp_data = $proc_net_tcp->{$inode}) {
                if ($tcp_data->{loc_ip} eq $MAILER_IP && $tcp_data->{loc_port} == $MAILER_PORT) {
                    $OffendersIP->{$tcp_data->{rem_ip}}{PIDs}{$pid} = $OffendersPID->{$pid}{count};
                    log_message(8, "Hooked up: me=$tcp_data->{loc_ip_port} -> them=$tcp_data->{rem_ip_port}");
                }
            }
        }
    } else {
        delete $OffendersPID->{$pid} if defined($OffendersPID->{$pid});
        log_message(1, "PID $pid has no open sockets but seems still running.") if -d "/proc/$pid";
    }
}

sub handle_offender_ip {
    my ($rem_ip, $OffendersIP, $white_list) = @_;
    my $total_offenses = 0;

    foreach my $pid (keys %{$OffendersIP->{$rem_ip}{PIDs}}) {
        $total_offenses += $OffendersIP->{$rem_ip}{PIDs}{$pid};
        if (defined $OffendersPID{$pid}) {
            $OffendersIP->{$rem_ip}{last_offense} = $OffendersPID->{$pid}{last_offense}
                if $OffendersPID->{$pid}{last_offense} > $OffendersIP->{$rem_ip}{last_offense};
        }
    }

    $OffendersIP->{$rem_ip}{offenses} = $total_offenses;
    log_message(5, "IP=$rem_ip has $total_offenses offenses, latest at " . GetYYYYMMDDHHMMSS_Pretty($OffendersIP->{$rem_ip}{last_offense}));

    if ($total_offenses > $MAX_OFFENSES_BEFORE_FIREWALLED && !$white_list->check(\$rem_ip) && !$OffendersIP->{$rem_ip}{firewalled}) {
        firewall_offender($rem_ip, $OffendersIP);
    } elsif ($white_list->check(\$rem_ip)) {
        log_message(1, "IGNORING WHITE-LISTED OFFENDER $rem_ip");
        delete $OffendersIP->{$rem_ip};
    }
}

sub firewall_offender {
    my ($rem_ip, $OffendersIP) = @_;
    
    $OffendersIP->{$rem_ip}{firewalled} = GetYYYYMMDDHHMMSS();
    my $cmd = "$IPTABLES_EXE -A '$IPTABLES_CHAIN_NAME' -p tcp -s '$rem_ip' --destination-port 25 -j DROP";
    $OffendersIP->{$rem_ip}{firewall_cmd} = $cmd;
    log_message(1, "FIREWALLING: $cmd");
    system_with_warning($cmd);

    foreach my $pid (keys %{$OffendersIP->{$rem_ip}{PIDs}}) {
        kill_sendmail_pid($pid, $rem_ip) if -e "/proc/$pid";
    }
}

sub kill_sendmail_pid {
    my ($pid, $rem_ip) = @_;
    log_message(1, "KILL -15ing SENDMAIL PID=$pid, related to IP=$rem_ip");
    kill 15, $pid;
    Time::HiRes::sleep(0.5);
    if (-e "/proc/$pid") {
        log_message(1, "KILL -9ing SENDMAIL PID=$pid, related to IP=$rem_ip");
        kill 9, $pid;
    }
}

# Initialize iptables rules/chain
sub initialize_iptables {
    my $cmd = "$IPTABLES_EXE -n -L '$IPTABLES_CHAIN_NAME'";
    my $exit_code = system_with_warning($cmd);

    if ($exit_code) {
        log_message(1, "The $IPTABLES_CHAIN_NAME chain needs to be created.");
        $cmd = "$IPTABLES_EXE -N '$IPTABLES_CHAIN_NAME'";
    } else {
        log_message(1, "The $IPTABLES_CHAIN_NAME chain needs to be flushed.");
        $cmd = "$IPTABLES_EXE -F '$IPTABLES_CHAIN_NAME'";
    }
    system_with_warning($cmd);

    my $RULE_SPEC = "INPUT -p tcp --destination-port 25 -j '$IPTABLES_CHAIN_NAME'";
    my $MAX_LOOPS = 10;
    do {
        $cmd = "$IPTABLES_EXE -D $RULE_SPEC";
        $exit_code = system_with_warning($cmd);
        $MAX_LOOPS--;
    } until ($exit_code || $MAX_LOOPS < 1);

    die "Unable to purge rule spec: $RULE_SPEC\n" if $MAX_LOOPS < 1;

    $cmd = "$IPTABLES_EXE -A $RULE_SPEC";
    system_with_warning($cmd);
}

# Load whitelist from file
sub load_whitelist {
    my $while_list_file = shift;
    open my $fh, '<', $while_list_file or die "Failed to load whitelist file: $while_list_file\n";
    
    my @subnets = grep { !/^#|^$/ } map { chomp; trim($_) } <$fh>;
    close $fh;

    my $sn = Net::Subnets->new;
    $sn->subnets(\@subnets);
    log_message(1, "Whitelist: " . join(',', @subnets));
    return $sn;
}

# System command wrapper with logging
sub system_with_warning {
    my $cmd = shift;
    my $retval = system("$cmd 1>/dev/null 2>/dev/null");
    my $exit_code = $retval / 256;
    log_message(1, "$cmd exited with $exit_code") if $exit_code;
    return $exit_code;
}

# Get socket inodes for offending processes
sub get_socket_inodes {
    my $cmd = "$FIND_EXE /proc -type l -path '*[0-9]/fd/*' -lname 'socket:*' -printf '%p\t%l\n' 2>/dev/null";
    my $mjr_krnl_ver = get_kernel_version();

    my %patterns = (
        '2.4' => "/proc/([0-9]+)/fd/[0-9]+\tsocket:\\[([0-9]+)]",
        '2.6' => "/proc/([0-9]+)/task/[0-9]+/fd/[0-9]+\tsocket:\\[([0-9]+)]"
    );
    
    open my $pipe, '-|', $cmd or log_message(0, "Error in get_socket_inodes(): command failed: $cmd");
    my %results;
    while (my $line = <$pipe>) {
        if ($line =~ /$patterns{$mjr_krnl_ver}/) {
            push @{$results{$1}}, $2;
        } else {
            log_message(0, "get_socket_inodes(): pattern match failed.");
        }
    }
    return \%results;
}

# Get kernel version
sub get_kernel_version {
    open my $fh, '<', "/proc/version" or return '2.4';
    my $ver_line = <$fh>;
    close $fh;
    return ($ver_line =~ /^Linux version ([0-9]+\.[0-9]+)/i) ? $1 : '2.4';
}

# Get process network TCP data
sub get_proc_net_tcp {
    open my $fh, '<', "/proc/net/tcp" or return;
    my @lines = <$fh>;
    close $fh;

    my %result;
    my @hdrs = split(/\s+/, trim(shift @lines));
    foreach my $line (@lines) {
        my @data = split(/\s+/, trim($line));
        my $inode = $data[9];
        if ($inode > 0) {
            my $loc_ip_port = convert_ip_port($data[1]);
            my $rem_ip_port = convert_ip_port($data[2]);
            if (length($rem_ip_port) && $rem_ip_port !~ /^127.0.0.1/) {
                my ($loc_ip, $loc_port) = split(/:/, $loc_ip_port);
                my ($rem_ip, $rem_port) = split(/:/, $rem_ip_port);
                $result{$inode} = {
                    loc_ip_port => $loc_ip_port,
                    loc_ip => $loc_ip,
                    loc_port => $loc_port,
                    rem_ip_port => $rem_ip_port,
                    rem_ip => $rem_ip,
                    rem_port => $rem_port
                };
            }
        }
    }
    return \%result;
}

# Convert IP and port from /proc/net/tcp format
sub convert_ip_port {
    my $addr = shift;
    if ($addr =~ /([0-9A-Z]{2})([0-9A-Z]{2})([0-9A-Z]{2})([0-9A-Z]{2}):([0-9A-Z]{2})([0-9A-Z]{2})/) {
        return join('.', map { hex($_) } ($4, $3, $2, $1)) . ":" . hex("$5$6");
    }
    return undef;
}

# Helper for trimming whitespace
sub trim {
    my $str = shift;
    $str =~ s/^[\s\r\n]+//;
    $str =~ s/[\s\r\n]+$//;
    return $str;
}

# Return formatted date and time
sub GetYYYYMMDDHHMMSS_Pretty {
    my $unix_time = shift || time;
    my ($sec, $min, $hour, $mday, $mon, $yr) = localtime($unix_time);
    return sprintf("%04d-%02d-%02d %02d:%02d:%02d", 1900 + $yr, $mon + 1, $mday, $hour, $min, $sec);
}

# Log messages to console or syslog
sub log_message {
    my ($level, $msg) = @_;
    return if $DEBUG <= $level;
    $msg =~ s/[\r\n]+$//;
    if ($DEBUG_TO_SYSLOG) {
        my $facility = 'user';
        my $priority = 'info';
        my $tag = "SPAM-FW[$$]";
        system($LOGGER_EXE, '-p', "$facility.$priority", '-t', $tag, $msg);
    } else {
        print "$msg\n";
    }
}

# Parse command-line options
sub parse_options {
    my %opts;
    GetOptions(
        'debug=i' => \$DEBUG,
        'debug-to-syslog' => \$DEBUG_TO_SYSLOG,
        'white-list=s' => \$WHITE_LIST,
        'syslog-msgs-file=s' => \$SYSLOG_MSGS_FILE,
        'mailer-ip=s' => \$MAILER_IP,
        'mailer-port=s' => \$MAILER_PORT,
        'mailer-syslog-host=s' => \$MAILER_SYSLOG_HOST,
        'mailer-syslog-name=s' => \$MAILER_SYSLOG_NAME,
        'iptables-chain-name=s' => \$IPTABLES_CHAIN_NAME
    ) or die "Error in command line arguments\n";

    # Validation of input options
    die "--white-list must refer to a readable text file.\n" unless -r $WHITE_LIST;
    die "--syslog-msgs-file must refer to a readable text file.\n" unless -r $SYSLOG_MSGS_FILE;
    die "--mailer-ip must be a valid IP address.\n" unless $MAILER_IP =~ /^(\d{1,3}\.){3}\d{1,3}$/;
    die "--mailer-port must be a valid IP port.\n" unless $MAILER_PORT =~ /^\d+$/ && $MAILER_PORT <= 65536;
    die "--mailer-syslog-host must not be empty.\n" unless length($MAILER_SYSLOG_HOST);
    die "--mailer-syslog-name must not be empty.\n" unless length($MAILER_SYSLOG_NAME);
    die "--iptables-chain-name must be alphanumeric.\n" unless $IPTABLES_CHAIN_NAME =~ /^[0-9a-z_]+$/i;
}

1;
