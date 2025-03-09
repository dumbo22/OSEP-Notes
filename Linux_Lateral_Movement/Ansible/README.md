# Ansible
## Enumeration

Query ansible hosts file to discover ansible clients and group names
```bash
cat /etc/ansible/hosts
```
## Ad-hoc commands
Commands can be executed on demand on ansible client systems
```bash
# Run as ansible admin
ansible <Group Name> -a "whoami"

# Runa as root
ansible <Group Name>-a "whoami" --become

# Run as specified user
ansible <Group Name> -a "whoami" --become --become-user=Moe
```

## Playbooks

Playbooks are a common method for automating and orchestrating tasks in Ansible. They allow multiple tasks to be scripted and executed as a routine, making them ideal for repetitive tasks such as:
- Setting up user accounts on new servers.
- Updating configurations or software on multiple machines.

Although playbooks are often run with elevated privileges, security-conscious administrators may restrict access by using dedicated users with minimal permissions necessary for the tasks. This helps reduce security risks and limits potential exploitation.

Example playbook:

```
---
- name: Get system info
  hosts: all
  gather_facts: true
  become: yes  # Enable privilege escalation for the entire playbook
  tasks:
    - name: Display info
      debug:
          msg: "The hostname is {{ ansible_hostname }} and the OS is {{ ansible_distribution }}"
```
The `hosts` value can be changed to target specific groups, invidiual systems or all to target everything. Using `become: yes` sets the playbook to run as the Root user. This can be optionally removed.


Playbooks can be executed trivially:
```bash
ansible-playbook getinfo.yml
```

Playbooks can also be used to run commands as a specified user

```
---
- name: Write a file as offsec
  hosts: all
  gather_facts: true
  become: yes
  become_user: offsec
  vars:
    ansible_become_pass: lab
  tasks:
    - copy:
          content: "This is my offsec content"
          dest: "/home/offsec/written_by_ansible.txt"
          mode: 0644
          owner: offsec
          group: offsec
```

In some instances ansible playbooks may contain encrypted passwords within. Providing we can read the file, it is possible to hash these and crack with JTR or Hashcat.

```
- name: Write a file as offsec
  hosts: all
  gather_facts: true
  become: yes
  become_user: offsec
  vars:
    ansible_become_pass: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          39363631613935326235383232616639613231303638653761666165336131313965663033313232
          3736626166356263323964366533656633313230323964300a323838373031393362316534343863
          36623435623638373636626237333163336263623737383532663763613534313134643730643532
          3132313130313534300a383762366333303666363165383962356335383662643765313832663238
          3036
  tasks:
    - copy:
          content: "This is my offsec content"
          dest: "/home/offsec/written_by_ansible.txt"
          mode: 0644
          owner: offsec
          group: offsec
```
When hashing, we need to ensure the hash is structured like so:

```
$ANSIBLE_VAULT;1.1;AES256
39363631613935326235383232616639613231303638653761666165336131313965663033313232
3736626166356263323964366533656633313230323964300a323838373031393362316534343863
36623435623638373636626237333163336263623737383532663763613534313134643730643532
3132313130313534300a383762366333303666363165383962356335383662643765313832663238
3036
```

Then hash with ansible2john.py
```python
python3 /usr/share/john/ansible2john.py ansible.yml > ansible.hash
```
The hash can then be cracked Hashcat. Ensure to remove the appended file name from the hash before cracking
```
ansible.yml:$ansible$0*0* --> $ansible$0*0*
```
```
# Hashcat
hashcat -m 16900 -a 0 -O ansible.hash rockyou.txt -r rules\best64.rule
```

Now the password is known, the original encrypted value, structured like below can be echoed into ansible-vault decrypt to reveal the plaintext contents of the encrypted playbook (after entering the decryption password).
```
$ANSIBLE_VAULT;1.1;AES256
39363631613935326235383232616639613231303638653761666165336131313965663033313232
3736626166356263323964366533656633313230323964300a323838373031393362316534343863
36623435623638373636626237333163336263623737383532663763613534313134643730643532
3132313130313534300a383762366333303666363165383962356335383662643765313832663238
3036
```

```
cat ansible.yml | ansible-vault decrypt
```

## Sensitive Data Leakage via Ansible Modules

In some instances Ansible playbooks may "leak" data to syslog.

```
cat /var/log/syslog
```
