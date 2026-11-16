# EC2 user data

[`user-data.sh`](./user-data.sh) installs and enrolls the agent on first boot. Put it in a launch template and every instance of the autoscaling group enrolls with the same token.

## Token in Parameter Store

The script reads the token from SSM Parameter Store, so it is not written into the launch template.

```bash
aws ssm put-parameter --name /zedr/enrollment-token --type SecureString --value 'zedr_fleet_...'
```

The instance profile needs `ssm:GetParameter` on that parameter, and `kms:Decrypt` when the parameter uses your own key. Set `ZEDR_SERVER_URL` and `ZEDR_TOKEN_PARAMETER` at the top of the script. The AMI needs the AWS CLI, which Amazon Linux ships and Ubuntu does not.

## Token in user data

Shorter, and weaker: user data is readable by every process on the instance through the metadata service and by everyone who can describe the launch template.

```sh
#!/bin/sh
curl -fsSL --retry 5 -H 'X-Zedr-Enrollment-Key: zedr_fleet_...' https://zedr.example.com/install.sh | sh
```

## Things to know

- Install at boot, not into the AMI. An AMI that contains `/var/lib/zedr/identity.json` gives every instance the same identity, and the control server raises `replay` incidents for them.
- Instances from one AMI often share `/etc/machine-id`. The agent id comes from the agent's own key, so they still enroll as separate agents.
- A terminated instance sends a shutdown notice and is shown as `stopped`. Nothing removes it from the console yet.
- An expired, exhausted or revoked token stops new instances from enrolling. Each attempt is recorded as an `enrollment_rejected` event with the reason.

Status: the script was run on Ubuntu 24.04 containers with systemd and a stand-in for the `aws` command. It has not been run on EC2.
