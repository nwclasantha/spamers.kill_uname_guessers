To run this Perl script, you will need to ensure that your environment is set up correctly and that the necessary dependencies are installed. Follow the steps below to execute the script:

![Au2sz3F1qDvcME2vFUMLbN](https://github.com/user-attachments/assets/29a5795b-4db7-44a9-9636-91d6b1f3ea53)

### 1. **Install Perl and Required Modules**
First, ensure that Perl is installed on your system. You can check this by running:

```bash
perl -v
```

If Perl is not installed, you can install it via your package manager. For example:

- On **Ubuntu** or **Debian**:

  ```bash
  sudo apt update
  sudo apt install perl
  ```

- On **CentOS** or **RHEL**:

  ```bash
  sudo yum install perl
  ```

Next, install the required Perl modules. This script uses several Perl modules that may not be installed by default, such as `File::Tail`, `FileHandle`, `Time::HiRes`, and `Net::Subnets`.

To install these modules, you can use `CPAN` (Perl's package manager):

```bash
sudo cpan install File::Tail FileHandle Time::HiRes Net::Subnets Getopt::Long
```

Alternatively, for systems using **APT** or **YUM**:
- On **Ubuntu/Debian**:

  ```bash
  sudo apt install libfile-tail-perl libtime-hires-perl libnet-subnets-perl
  ```

- On **CentOS/RHEL**:

  ```bash
  sudo yum install perl-Time-HiRes perl-File-Tail perl-Net-Subnets
  ```

### 2. **Make the Script Executable**
Ensure the script has executable permissions. If the script file is named `spam_kill_uname_guessers.pl`, you can make it executable by running:

```bash
chmod +x spam_kill_uname_guessers.pl
```

### 3. **Prepare Configuration Files**
Make sure you have the required configuration files, such as the whitelist file for IP addresses or subnets to be excluded from being blocked.

- **Whitelist File**: Create a file (e.g., `/etc/mail/spam.kill_uname_guessers.whitelist`) with a list of IPs or subnets in CIDR notation, one per line.

For example:

```
192.168.0.0/24
10.10.10.0/24
```

### 4. **Run the Script with Command-Line Options**
You need to run the script with the appropriate command-line options, such as specifying the syslog file, mailer IP, and port.

Here’s an example of how to run the script:

```bash
./spam_kill_uname_guessers.pl --debug=3 --debug-to-syslog \
 --white-list=/etc/mail/spam.kill_uname_guessers.whitelist \
 --syslog-msgs-file=/var/log/messages \
 --mailer-ip=10.100.10.200 --mailer-port=25 \
 --mailer-syslog-host=mail1 --mailer-syslog-name=sm-mta \
 --iptables-chain-name=SPAM_UNAME_GUESSERS
```

This command:
- Enables debugging at level 3 and logs debug information to syslog.
- Specifies the whitelist file for IPs/subnets.
- Monitors `/var/log/messages` for syslog data.
- Defines the mailer IP (`10.100.10.200`) and port (`25`).
- Specifies the syslog host (`mail1`) and tag (`sm-mta`) for filtering logs.
- Sets the iptables chain to `SPAM_UNAME_GUESSERS` to manage DROP rules for spammers.

### 5. **Running as a Daemon**
To run this as a daemon, you can integrate it into your system’s process management. For example, you could create a systemd service to manage the script. Here’s an example of a basic systemd service file (`/etc/systemd/system/spam_filter.service`):

```ini
[Unit]
Description=Spam Filter to Block Username Guessers
After=network.target

[Service]
ExecStart=/path/to/spam_kill_uname_guessers.pl --debug=3 --debug-to-syslog \
 --white-list=/etc/mail/spam.kill_uname_guessers.whitelist \
 --syslog-msgs-file=/var/log/messages \
 --mailer-ip=10.100.10.200 --mailer-port=25 \
 --mailer-syslog-host=mail1 --mailer-syslog-name=sm-mta \
 --iptables-chain-name=SPAM_UNAME_GUESSERS
Restart=always
User=root

[Install]
WantedBy=multi-user.target
```

After saving the file, enable and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable spam_filter.service
sudo systemctl start spam_filter.service
```

### 6. **Monitoring and Logs**
The script will log its activity either to syslog or to the console, depending on how you configure the `--debug` and `--debug-to-syslog` options.

- To check the logs, you can use:

```bash
tail -f /var/log/syslog  # or /var/log/messages depending on your system
```

If you configured the script to log via syslog, you can see its output here.

### 7. **iptables Management**
The script will automatically manage `iptables` rules for blocking spammers. You can view the rules using:

```bash
sudo iptables -L SPAM_UNAME_GUESSERS
```

This will display the list of IP addresses that have been blocked by the script.

### 8. **Stop the Script**
If you want to stop the script manually, simply terminate the process or stop the systemd service if running as a daemon:

```bash
sudo systemctl stop spam_filter.service  # if running as a systemd service
```

### Conclusion
Running this script involves setting up Perl and its modules, preparing configuration files like the whitelist, and ensuring proper execution with appropriate command-line options. Once set up, the script will continuously monitor your mail logs, detect spammers, and dynamically apply firewall rules to block them.
