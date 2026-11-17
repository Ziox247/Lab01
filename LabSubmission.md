# Lab01: Identity Lifecycle Management and Security Controls on the AWS Free Tier

## Nimbus Identity Console: Written Submission

## Lab results summary

- **Part A (tests).** `./run_tests.sh unit` passed all 256 unit tests and `./run_tests.sh integration` passed all 13 integration tests. The tests use a mock of AWS, so they prove the logic and the policy files, not the live account.
- **Parts B to F (deployment).** The bootstrap scripts created the groups, policies, buckets, secrets, service roles, CloudTrail trail, alerts and the hardened EC2 server. The console was reached over HTTPS on port 8443 after I compared the certificate fingerprint with the value in the EC2 console output.
- **Part G (company).** I signed in as `admin` with the password stored in the `nimbus/web-login` secret. The Dashboard loaded, and I onboarded the 10 employees, offboarded emily, and confirmed that onboarding her again is refused.
- **Part H (experiments).** G1 to G6 were run against the live account. The answers below explain each result and name the control responsible.
- **Part J (cleanup).** The usage report was recorded first, then `99-cleanup.sh` removed the lab resources.

---

## Part A: Run the Tests Locally

### Q1 (explore). Tests as security controls

I would run the unit, policy and integration tests in the delivery pipeline at three points: locally before a commit, on every pull request, and again on the main branch immediately before deployment. The pull request run must be a required status check under branch protection, so a failing security test blocks the merge and nothing unmerged can reach production. The deployment job should run only from the main branch and should re-run the tests, because a branch that merged late could otherwise skip them.

Tests cannot catch two kinds of problem. First, they cannot catch anything that only exists in the live environment: the tests run against a mock of AWS, so real AWS behaviour (eventual consistency, a console change made by hand, drift after deployment) is invisible to them. Second, they cannot catch properties that nobody wrote a test for, which includes newly disclosed vulnerabilities in dependencies and attack paths nobody imagined.

Policy-as-code and analysis tools sit alongside these tests rather than replacing them. IAM Access Analyzer policy validation checks a policy against IAM grammar and security best practices and can flag over-broad statements without any custom test code [1]. AWS CloudFormation Guard and Open Policy Agent evaluate declarative rules against templates or plans, and one rule set can be reused across many repositories [2][3]. The Lab01 tests are bespoke: they encode this repository's own intent, such as "the launch script never opens port 22", which a generic rule set does not know. A secret scanner such as the credential check in `create_repo.sh` does a different job again. It searches content for credential patterns (an `AKIA...` key or a private key header) and runs at the commit boundary, which is where a leaked secret in a public repository does its damage [4]. The four approaches complement each other.

---

## Part B: IAM Groups and Policies

### Q2. Why does Nimbus-RequireMFA use BoolIfExists rather than Bool?

The key `aws:MultiFactorAuthPresent` is only present in a request that was made with temporary credentials from an MFA-authenticated session; requests signed with long-term credentials such as an access key do not carry the key at all [5]. The guard is a Deny, and a Deny only applies when its condition matches. With a plain `Bool` condition an absent key makes the condition false, so the Deny would not apply and an access key would bypass the guard. `BoolIfExists` treats a missing key as a match, so the Deny applies both when the value is `"false"` and when the key is absent. The guard therefore fails closed.

### Q3. In TechTeam-DevScoped, why is a Deny still useful when no Allow grants IAM access?

With no Allow, IAM already denies by default, but that is an implicit deny, and any later Allow overrides it. A user can belong to several groups, can have inline or managed policies attached later, and could be given a broad policy by mistake. An explicit Deny cannot be overridden by any Allow [6], so the Deny on actions such as `iam:CreateUser`, `iam:AttachUserPolicy`, `iam:PassRole` and `billing:*` is a guarantee that holds even if someone adds a wide Allow in future. It turns "nobody has granted this yet" into "this can never be granted through this group".

### Q4 (explore). Group membership as an escalation path

The most valuable group to join would be **SecurityTeam**. Its policy `SecurityTeam-IAMAudit` has the statement `AuthorOnlyNimbusPolicies`, which allows `iam:CreatePolicy`, `iam:CreatePolicyVersion` and `iam:DeletePolicyVersion` on `policy/nimbus/*`. That path contains every policy in the lab, including `SecurityTeam-IAMAudit` itself, so a member can create a new default version of their own group's policy that allows `*` and so make themselves an administrator. A member could also rewrite `Nimbus-DenyAll` into an empty document, which silently breaks the kill switch for every offboarded user, or rewrite `Nimbus-RequireMFA` to remove the MFA guard. The MFA guard itself is no obstacle to an attacker who controls the onboarding service, because the guard allows the user to enrol an MFA device by themselves. Even without escalation the group can read IAM broadly, which gives an attacker a map of the account.

Three ways to close the gap:

- **A condition or resource scope on group names.** The statement `AddToNimbusGroupsOnly` allows `iam:AddUserToGroup` on `group/nimbus/*`. Listing only `group/nimbus/TechTeam` and `group/nimbus/BusinessTeam` as resources means the role cannot add anyone to SecurityTeam. It is precise, free, and sits where the problem is.
- **A permissions boundary.** A boundary sets the maximum permissions a user or role can ever have, whatever its groups grant [7]. Applied to the users the onboarding service creates, it caps what a user added to SecurityTeam could do, and it is a good second layer because it limits the damage as well as the membership. It is more work to maintain, because the boundary must be attached at creation and the onboarding role must be restricted to attaching only that boundary.
- **A Service Control Policy.** An SCP gives a guardrail that account administrators cannot remove, but it needs AWS Organizations, grants nothing, and is too blunt to express "onboarding may add to these two groups" for one role.

I would choose the resource scope first, because it fixes the actual over-permission with no new infrastructure, and add the permissions boundary as defence in depth. At company scale I would add an SCP above both. I would also alert on `AddUserToGroup` into SecurityTeam, because the current alert rules do not cover it (see Q11).

---

## Part C: Buckets, Secrets and Data Protection

### Q5. Three places the admin password could have ended up without Secrets Manager

1. **Source code or a config file in git.** The lab repository is public, so a password committed there is readable by anyone on the internet and stays in git history even after the file is changed.
2. **An environment variable, `.env` file or Docker image layer.** Anything baked into an image or compose file is readable with `docker inspect`, copied into every image layer and registry, and travels with every copy of the image. A secret in an image can never be fully withdrawn.
3. **EC2 user-data, shell history or logs.** User-data can be read from the instance metadata service by any process on the host and is visible in the EC2 console, and command history and application logs are kept, shipped and read by people and systems who do not need the credential.

Each is worse than Secrets Manager because the credential is copied into places with different readers, different retention and no access audit. Secrets Manager keeps one encrypted copy, gates every read with IAM and records each read in CloudTrail.

### Q6. What does the TLS only bucket policy stop that Block Public Access does not?

Block Public Access controls who may be granted access (public ACLs and public policies). It says nothing about how a legitimate, authorized request travels. A properly signed request from an IAM role over plain HTTP still passes Block Public Access, and its data and signature headers can be read or tampered with on the network. The bucket policy adds two explicit Denies: `aws:SecureTransport = false` refuses any request made over plain HTTP, and `s3:TlsVersion` below 1.2 refuses old TLS versions. In G5 the same `list-objects-v2` call made with an `http://` endpoint failed with an explicit deny in the resource policy and the HTTPS call succeeded. The two controls protect different things: one stops exposure, the other stops eavesdropping and tampering.

### Q7 (explore). Customer managed keys

Default encryption (SSE-S3 and the default Secrets Manager key) protects against lost or stolen disks, but access to the plaintext is controlled only by S3 or Secrets Manager permissions, and AWS-managed keys give no per-key control. A customer managed KMS key adds threats it can address: a principal with broad S3 permissions still cannot read data unless the key policy also lets it use the key, so a stolen S3 role is not enough; every use of the key is a separate CloudTrail record; and the owner can disable the key or schedule it for deletion, which makes the protected data unreadable as an emergency control [8].

A key policy separates duties by using two statements. The first allows a key administrator role to manage the key (`kms:Create*`, `kms:Describe*`, `kms:Enable*`, `kms:Put*`, `kms:Update*`, `kms:Disable*`, `kms:ScheduleKeyDeletion`) but not to use it for data. The second allows the application roles (here the four service roles) to use it (`kms:Encrypt`, `kms:Decrypt`, `kms:GenerateDataKey*`, `kms:DescribeKey`), optionally restricted with `kms:ViaService` to S3 in the lab's region. Neither group can do the other's job.

The costs are a monthly fee per key plus per-request charges, which is why the lab guards against creating one. The failure modes are real: a mistaken key policy can lock everyone out, a disabled or deleted key makes data permanently unreadable, a service role that loses `kms:Decrypt` causes an outage, and request throttling can slow busy services.

---

## Part D: One IAM Role per Microservice

### Q8. The three simulator results

All three simulations use the principal `role/nimbus/nimbus-onboarding-svc`.

| # | Action | Resource | Request context | Decision | Deciding statement |
|---|--------|----------|-----------------|----------|--------------------|
| 1 | `iam:AttachUserPolicy` | `user/nimbus/alice` | `iam:PolicyARN` = `arn:aws:iam::aws:policy/AdministratorAccess` | implicitDeny | `AttachOnlyTheMFAGuardPolicy` matches the action and resource, but its `ArnEquals` condition on `iam:PolicyARN` fails, and no other statement allows the action, so the default deny applies. |
| 2 | `iam:AttachUserPolicy` | `user/nimbus/alice` | `iam:PolicyARN` = `.../policy/nimbus/Nimbus-RequireMFA` | allowed | `AttachOnlyTheMFAGuardPolicy`: action, resource and the `ArnEquals` condition all match. |
| 3 | `iam:CreateLoginProfile` | `user/lab-user` | none relevant | implicitDeny | `CreateAndTagNimbusUsersOnly` allows this action, but only on `user/nimbus/*`. `lab-user` is outside that path, so no statement matches and the default deny applies. |

None of the three results comes from an explicit Deny; they are all implicit denies caused by a narrow Allow that does not match.

### Q9 (explore). Four containers, one host

The server's only identity is the instance role, and its credentials are served by the instance metadata service (IMDSv2). The role's policy allows `sts:AssumeRole` on `role/nimbus/nimbus-*-svc`, and each service role's trust policy names the instance role as the only principal that may assume it. IMDS responses have a network hop limit; with a limit of 1 the response would be dropped at the Docker bridge, but the lab sets `HttpPutResponseHopLimit=2` so that containers can reach IMDS [9]. As a result any code running in any container can fetch the instance role's credentials and assume any of the four service roles. A compromised `web` container, which has no IAM or S3 permission of its own, could assume `nimbus-onboarding-svc` and create users.

| Redesign | Isolation | Cost | Operational effort |
|---|---|---|---|
| One instance per service | Strong: each instance has its own role and the hop limit problem disappears. | Four instances burn the free-tier hours about four times faster, so it leaves the free tier. | Four hosts to patch, harden, monitor and shut down. |
| Container task roles on Amazon ECS | Strong: each task gets its own role through the task credentials endpoint and can be blocked from the instance role [10]. | The ECS control plane is free; EC2 capacity costs the same, Fargate adds per-vCPU charges. | Moderate: task definitions, cluster and service configuration. |
| Pod-level identity on Kubernetes (EKS Pod Identity) | Strong: credentials are bound to the pod's service account [11]. | The managed control plane has an hourly charge, so it is not free. | Highest: a cluster, node management, add-ons and Kubernetes skills. |

For production I would choose separate ECS task roles, because they give per-service identity with much less operating work than Kubernetes and without multiplying hosts.

---

## Part E: Logging and Alerts

### Q10. Which two kinds of event does the lab alert on, and why alert instead of only storing them?

The lab alerts on (1) risky IAM changes, through the rule `lab01-risky-iam`: creating an access key, writing an inline, group or role policy, creating a policy version, changing a trust policy, removing a permissions boundary, or attaching `AdministratorAccess`; and (2) successful console sign-ins without MFA, through the rule `lab01-signin-without-mfa`. Both reach an email address through EventBridge and SNS. Storing events lets you reconstruct an incident afterwards, but nobody reads a log bucket in real time. Both event types are early steps of an attack (persistence and credential abuse), so a notification within minutes is what turns evidence into a chance to contain the incident before damage is done.

### Q11 (explore). Blind spots in detection

The rules would miss at least these two attacker actions:

1. **Creating or changing a console password for an existing user** (`CreateLoginProfile`, `UpdateLoginProfile`). This is not in the risky-IAM list, and the user's later console sign-in only alerts if MFA was not used.
2. **Adding a user to a privileged group or attaching a broad managed policy other than `AdministratorAccess`.** The rule matches `AttachUserPolicy` only when the policy ARN is exactly `AdministratorAccess`, and `AddUserToGroup` is not matched at all, so putting a user into SecurityTeam, or attaching `IAMFullAccess`, produces no alert. Stolen credentials used from an unusual location are also invisible to these two rules.

An event pattern for the first one:

```json
{
  "source": ["aws.iam"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["iam.amazonaws.com"],
    "eventName": ["CreateLoginProfile", "UpdateLoginProfile"]
  }
}
```

Like the other two rules, it would have to be created in us-east-1, because that is where IAM events are emitted.

Every extra rule also creates alert fatigue. If routine events (the onboarding service itself calls `CreateLoginProfile` legitimately) generate emails, people stop reading them, so alerts need tuning, such as filtering out the known service roles. Amazon GuardDuty approaches the problem differently: it analyses CloudTrail, VPC flow logs and DNS logs with managed threat intelligence and anomaly detection, ranks findings by severity, and updates its detections itself, so you do not write and maintain each pattern [12]. It is a paid service after its trial period.

---

## Part F: Launch the Hardened Server

### Q12. Why is there no SSH and no key pair, and how do you debug the server without them?

An open SSH port is a remote administration path that attackers scan for constantly, and a key pair is a long-lived credential that can be stolen or shared. With neither, there is nothing to log in to, which removes an entire attack surface. Debugging uses other channels: the boot log written to the instance console (`aws ec2 get-console-output` showed the certificate fingerprint and the "lab01 ready" line), the container logs that the Docker awslogs driver ships to CloudWatch Logs group `/lab01/app`, and the REJECT-only flow logs in `/lab01/flow`. If the server is broken beyond repair, the design is to terminate it and launch a fresh one, since it holds no state.

### Q13. If the web container were compromised, what does egress filtering stop and what does it not stop?

Because the security group allows outbound traffic only on TCP 443 and 80, it stops a reverse shell or command-and-control channel on an unusual port, scanning of other hosts on other ports, and transfers over protocols such as SSH or FTP. It does not stop exfiltration over HTTPS to any destination, because 443 is open to the whole internet and security groups cannot filter by hostname. DNS and the instance metadata service are not filtered by security groups, so data can be tunnelled through DNS, and the container can still reach IMDS to obtain the instance role credentials and assume other service roles (see Q9). The S3 gateway endpoint policy limits only the S3 route to our bucket, which is a useful speed bump, but not a complete wall.

### Q14 (explore). Certificates and trust on first use

The self-signed certificate has no authority behind it, so the only way to know it belongs to my server is to compare its SHA-256 fingerprint with the value I read from the EC2 console output. The comparison defends against a man-in-the-middle attack in which someone on the network path presents their own self-signed certificate. Without the comparison, the browser warning looks the same for the real server and for the attacker, and trusting the first certificate you see is exactly the trust-on-first-use weakness. Most users skip it because the warning is common, the comparison is a manual and unfamiliar task, and clicking through is quicker.

A certificate from AWS Certificate Manager removes the manual step, because browsers validate a chain to a trusted authority. ACM public certificates cannot be exported, so they are used with integrated services such as a load balancer [13], and a load balancer is one of the paid resources that the lab's scripts are tested never to create. A certificate from a public certificate authority gives the same browser validation directly on the instance, but needs a domain name that the lab does not have. HSTS adds a browser rule to use HTTPS only for a site for a stated time and not to allow click-through on certificate errors [14]. Certificate Transparency adds public, append-only logs of issued certificates, so a certificate that an authority wrongly issues for your domain can be detected [15]. Neither applies to a self-signed certificate.

---

## Part H: Security Experiments

### Q15. Which of the six checks proved what?

The six checks in G4 were: HTTPS works, plain HTTP fails, the security headers, the SSH and old-port probes, the lockout test, and the listing of the rules I built.

- **Encryption in transit:** the HTTPS request returned a normal response, and the plain HTTP request to the same port failed. Together they show that the console is reachable only over TLS.
- **Smaller attack surface:** the port probes (22 and 8080 did not answer) and the security group and endpoint listing (one inbound rule, TCP 8443 from my address only, outbound limited to 80 and 443, and a gateway endpoint for S3) show that almost nothing is exposed.
- **Protection against password guessing:** the lockout test, six wrong passwords returning 200 five times and then 429, shows that guessing is throttled by the application.

The headers check is a separate, browser-side defence (CSP, X-Frame-Options, HSTS and similar), and does not fall under any of the three questions.

### Q16. Why does the same user and action get denied without MFA and allowed with it?

The only thing that changes between the two simulator runs is the request context key **`aws:MultiFactorAuthPresent`**. The guard policy contains a Deny with `"BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}` on everything except password change and MFA setup. When the context says `false`, the condition matches, the explicit Deny applies and it beats the user's group Allow. When the context says `true`, the condition is false, the Deny does not apply, and the group's Allow permits `ce:GetCostAndUsage`. The same happened in the live test: james could only set a new password until he enrolled a virtual MFA device, after which the Dashboard moved him from MFA PENDING to OK.

### Q17. Who created mallory and how did you find out? Why does the audit trail in S3 not show it?

The IAM user mallory was created by the lab user (`lab-user`), because I ran `aws iam create-user --user-name mallory --path /nimbus/` myself. I found out in two ways: the Dashboard flagged mallory as UNTRACKED (a user under `/nimbus/` with no registry record), and `./08-investigate.sh mallory` showed a `CreateUser` event in CloudTrail naming the caller and the source address. The S3 audit trail does not show it because the audit objects are written only by the onboarding and offboarding services when they do something. Mallory was created straight against IAM, so the application never knew about it, and that gap is the evidence. It also shows why the three sources must be compared: CloudTrail is outside the application's control, while the application's own records only describe what the application did.

### Q18 (explore). Replacing IAM users with single sign on

With IAM Identity Center and an external identity provider [16], the company would no longer need IAM users, temporary passwords, per-user login profiles, the console admin password, the onboarding service that creates users, or the per-user MFA enrolment and deadline logic, because users, groups and MFA live in the identity provider and access arrives as short-lived role sessions.

Several things would still matter. The kill switch idea remains: a leaver must be cut off at once, by disabling the user in the identity provider, revoking their sessions and removing their assignments, with an explicit deny as a backstop. Drift detection remains, now comparing identity provider assignments with live permission sets. Least-privilege service roles, CloudTrail, the alerts and the investigation procedure all still apply. MFA still matters but is enforced at the identity provider.

New risks appear. A compromised identity provider or its administrator can sign in as anyone, so it becomes the most valuable target. Federation misconfiguration, stolen SSO sessions and tokens, overly broad permission sets assigned to groups, provisioning errors between the provider and AWS, and an identity provider outage that locks everyone out are all possible. The mitigations are strong phishing-resistant MFA and conditional access for provider administrators, monitoring of provider changes, short sessions, and a tightly controlled break-glass account.

---

## Part H: Data Proofs and Incident Drill

### Q19. Why is a token rotation safe with no restart, and what would break if the services accepted only the current token?

`put-secret-value` makes the new token `AWSCURRENT` and demotes the old one to `AWSPREVIOUS`. Every service accepts both versions, so a caller that still holds the old token is not rejected while caches catch up (each service caches the secret for 60 seconds). A service that is rejected also refreshes its cache once, at most every 5 seconds, and logs `internal_token_refreshed`, so it converges without a restart. If services accepted only the current token, there would be a window after each rotation in which the web service, still sending the old cached token, would be refused with HTTP 401 by workers that had already refreshed, so the Dashboard and Onboard pages would fail until the caches expired. Rotation would then need a coordinated restart or planned downtime, and people would avoid doing it.

### Q20. Which control would have prevented the incident, and which only limited it?

In the drill an attacker with the lab user's stolen credentials plants a backdoor access key on james. Nothing inside the lab's own design prevented the key being created, because the lab user is an administrator and the guard policy applies to the nimbus users, not to the administrator acting on them. What would have prevented it is protecting the administrator's credentials: no long-lived administrator access keys, and a policy that denies the administrator's actions unless `aws:MultiFactorAuthPresent` is true, which a stolen access key cannot satisfy.

The controls the lab does have limited the damage. The `lab01-risky-iam` alert detected the `CreateAccessKey` event within minutes. `Nimbus-DenyAll`, attached by offboarding, made the backdoor key useless immediately, because an explicit Deny beats every Allow, and the investigation script and CloudTrail identified the caller. One more free control I would add is an explicit Deny on `iam:CreateAccessKey` for everything under `/nimbus/`, applied through a permissions boundary or an SCP. In this design nobody needs access keys, since people use the console and services use roles, so the Deny costs nothing and removes the whole path.

### Q21 (explore). Mapping the drill to a framework

**MITRE ATT&CK Cloud Matrix** [17]:

- Using the lab user's stolen credentials is **T1078.004, Valid Accounts: Cloud Accounts**.
- Planting the backdoor key on james is **T1098.001, Account Manipulation: Additional Cloud Credentials** (persistence).
- Listing users, groups and keys beforehand would be **T1087.004, Account Discovery: Cloud Account**.

The defender's steps map to the NIST incident response lifecycle [20]: detection is the alert email, analysis is `08-investigate.sh`, containment is offboarding with `Nimbus-DenyAll`, eradication is deleting the backdoor key, recovery is onboarding `james2`, and the post-incident review reads the REJECT flow logs.

**Three lab controls mapped to NIST SP 800-53 Rev. 5 and the CIS AWS Foundations Benchmark** [18][19]:

1. The MFA guard maps to NIST IA-2(1) (multi-factor authentication for privileged accounts) and to the CIS recommendation that IAM users with a console password have MFA enabled.
2. The kill switch and layered offboarding map to NIST AC-2 (account management, including disabling accounts promptly).
3. CloudTrail with log file validation maps to NIST AU-2 and AU-12 (event logging and audit record generation) and to the CIS logging recommendations, including log file validation.

**A requirement the lab does not meet:** CIS recommends CloudTrail enabled in all regions, and the lab uses a single-region trail (`--no-is-multi-region-trail`) to stay within the free copy of management events. On the NIST side, AU-9 (protection of audit information) is only partly met: the S3 audit objects are not immutable, since no Object Lock is configured.

---

## Part I: From 10 to 100 People

### Q22. The scaling table in my own words

| Concern | Limit hit first | What I would change |
|---|---|---|
| Permissions | The 10-groups-per-user limit would only matter if people needed many roles, and the 5,000-user account quota is far away. At 100 people neither is hit. | Keep three groups. Review group design as roles multiply and plan for more accounts or SSO well before 5,000 users. |
| Registry | Listing the `registry/` prefix on every refresh becomes slow at around 10,000 objects. | Keep one object per person, but add an index or a database table and paginate the listing instead of reading everything. |
| Dashboard | The cost of about five IAM calls per user per refresh, which is the first real limit: 100 users means roughly 500 calls per refresh, and it grows from there. | Keep the 15-second cache and parallel workers for now. Above about 1,000 users switch to the IAM credential report. |
| Service identity | Not a scale limit but a security limit: all four containers share one host, so a compromised container could assume any service role. | Give each service its own identity with separate ECS task roles or separate hosts. |
| Sign in | A single shared admin password with an in-memory lockout does not scale to several administrators. | Replace it with SSO and stop creating IAM users. |
| Logging | More users mean more CloudTrail events, and the short retention periods lose evidence. | Move to a central log archive account and a SIEM, with retention based on investigation needs. |

---

## Part I (continued): Controls an Administrator Cannot Remove

### Q23 (explore). Service Control Policies for three controls

An SCP applied from AWS Organizations sets a ceiling on what principals in member accounts can do, and a Deny in it cannot be overridden by the account's own administrators [21]. The three SCPs below protect the trail, the `Nimbus-DenyAll` policy and S3 Block Public Access. Each exempts one break-glass role, so that a tightly controlled break-glass role can still do legitimate maintenance.

**1. Protect the CloudTrail trail:**

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "ProtectLab01Trail",
    "Effect": "Deny",
    "Action": [
      "cloudtrail:StopLogging",
      "cloudtrail:DeleteTrail",
      "cloudtrail:UpdateTrail",
      "cloudtrail:PutEventSelectors"
    ],
    "Resource": "arn:aws:cloudtrail:*:*:trail/lab01-trail",
    "Condition": {
      "ArnNotLike": {"aws:PrincipalArn": "arn:aws:iam::*:role/SecurityBreakGlass"}
    }
  }]
}
```

**2. Protect the Deny All policy** (the document cannot be changed and the policy cannot be detached):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ProtectDenyAllDocument",
      "Effect": "Deny",
      "Action": [
        "iam:DeletePolicy",
        "iam:CreatePolicyVersion",
        "iam:DeletePolicyVersion",
        "iam:SetDefaultPolicyVersion"
      ],
      "Resource": "arn:aws:iam::*:policy/nimbus/Nimbus-DenyAll",
      "Condition": {
        "ArnNotLike": {"aws:PrincipalArn": "arn:aws:iam::*:role/SecurityBreakGlass"}
      }
    },
    {
      "Sid": "DoNotDetachDenyAll",
      "Effect": "Deny",
      "Action": [
        "iam:DetachUserPolicy",
        "iam:DetachGroupPolicy",
        "iam:DetachRolePolicy"
      ],
      "Resource": "*",
      "Condition": {
        "ArnLike": {"iam:PolicyARN": "arn:aws:iam::*:policy/nimbus/Nimbus-DenyAll"},
        "ArnNotLike": {"aws:PrincipalArn": "arn:aws:iam::*:role/SecurityBreakGlass"}
      }
    }
  ]
}
```

**3. Keep S3 Block Public Access on** (the permission that removes it, `s3:PutBucketPublicAccessBlock`, is also what `DeletePublicAccessBlock` requires):

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "KeepBlockPublicAccessOn",
    "Effect": "Deny",
    "Action": [
      "s3:PutAccountPublicAccessBlock",
      "s3:PutBucketPublicAccessBlock"
    ],
    "Resource": "*",
    "Condition": {
      "ArnNotLike": {
        "aws:PrincipalArn": [
          "arn:aws:iam::*:role/SecurityBreakGlass",
          "arn:aws:iam::*:role/Lab01Provisioning"
        ]
      }
    }
  }]
}
```

The provisioning role is exempt here because the lab's own bucket script calls `put-public-access-block` when it creates a bucket.

**What an SCP does not protect against.** An SCP grants no permissions by itself; it only limits them. It does not affect principals in the management account, service-linked roles, or principals outside the organization that reach resources through resource-based policies. It also protects only the actions it names: a deny on `StopLogging` does nothing about someone deleting objects in the log bucket, so the protected set must be thought through. And whoever can edit or detach the SCP itself can remove the protection.

**Why the management account is different.** SCPs are not applied to the management account, because it is the account that administers the organization, including the SCPs, and AWS does not allow it to be locked out of its own organization. That makes it the most privileged account, so it must hold no workloads, have very few users, require strong MFA, and be closely monitored.

---

## Part J: Clean Up

### Q24 (explore). Can you trust the logs?

With log file validation on, CloudTrail delivers a digest file every hour. Each digest contains the SHA-256 hash of every log file delivered in that period, is signed by CloudTrail, and includes the hash of the previous digest, forming a chain [22]. This proves that a log file was not modified, replaced or deleted after delivery and that the chain has no missing links. It is verified with the AWS CLI, for example:

```
aws cloudtrail validate-logs \
  --trail-arn arn:aws:cloudtrail:us-east-1:ACCOUNT_ID:trail/lab01-trail \
  --start-time 2026-11-01T00:00:00Z
```

The command reports each digest and log file as valid or names the files that are missing or altered. It does not prove completeness: it cannot show that every event was recorded, since the trail is single-region and records no data events, and it cannot prove that nobody turned logging off before the events happened.

An attacker with administrator rights could still do a great deal to the evidence in this lab. They could stop or delete the trail, change the log bucket policy or lifecycle rules to expire logs early, delete log objects and the digest files with them, delete the audit and registry objects in the data bucket (including old versions), delete the CloudWatch log groups, and disable the EventBridge rules or the SNS subscription so that nobody is alerted. Validation would reveal tampering with delivered files, but it cannot recover evidence that was deleted together with its digests, or events that were never logged because the trail had been stopped.

Three controls change the answer [22][23]. A separate log archive account that receives the trail's logs means a compromised workload account has no permissions in the archive, so the attacker cannot delete what is stored there. S3 Object Lock in compliance mode makes objects write-once for a retention period that nobody, including the root user, can shorten, which defeats deletion and early expiry. MFA delete requires a second factor to permanently delete versions or change versioning, which raises the bar but is weaker than Object Lock and can be enabled only by the bucket owner's root user. These controls should be managed by different people from the workload administrators.

---

## Appendix: G6 incident drill timeline

| Phase (NIST lifecycle) | Action | Timestamp |
|---|---|---|
| Preparation | Trail, alerts, roles, kill switch and investigate script already in place | n/a |
| Detection | Backdoor key created for james; `lab01-risky-iam` email received | T0 = `__________`  alert = `__________` |
| Analysis | `08-investigate.sh james` found `CreateAccessKey`, the caller and the source address | `__________` |
| Containment | james offboarded; `Nimbus-DenyAll` attached and keys deactivated | `__________` |
| Eradication | Backdoor key deleted; Dashboard shows james as CLOSED | `__________` |
| Recovery | Replacement account `james2` onboarded (persona developer) | `__________` |
| Post incident | REJECT records from the G4 probes read in `/lab01/flow` | `__________` |

---

## References

1. AWS, "IAM Access Analyzer policy validation": https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-policy-validation.html
2. AWS, "AWS CloudFormation Guard": https://docs.aws.amazon.com/cfn-guard/latest/ug/what-is-guard.html
3. Open Policy Agent documentation: https://www.openpolicyagent.org/docs/latest/
4. GitHub Docs, "About secret scanning": https://docs.github.com/en/code-security/secret-scanning/introduction/about-secret-scanning
5. AWS, "AWS global condition context keys" (`aws:MultiFactorAuthPresent`): https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html
6. AWS, "Policy evaluation logic": https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html
7. AWS, "Permissions boundaries for IAM entities": https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html
8. AWS, "Key policies in AWS KMS": https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html
9. AWS, "Configure the Instance Metadata Service options": https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html
10. AWS, "Amazon ECS task IAM role": https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html
11. AWS, "Learn how EKS Pod Identity grants pods access to AWS services": https://docs.aws.amazon.com/eks/latest/userguide/pod-identities.html
12. AWS, "What is Amazon GuardDuty?": https://docs.aws.amazon.com/guardduty/latest/ug/what-is-guardduty.html
13. AWS, "What is AWS Certificate Manager?": https://docs.aws.amazon.com/acm/latest/userguide/acm-overview.html
14. IETF, RFC 6797, "HTTP Strict Transport Security (HSTS)": https://datatracker.ietf.org/doc/html/rfc6797
15. IETF, RFC 9162, "Certificate Transparency Version 2.0": https://datatracker.ietf.org/doc/html/rfc9162
16. AWS, "What is IAM Identity Center?": https://docs.aws.amazon.com/singlesignon/latest/userguide/what-is.html
17. MITRE ATT&CK, Cloud Matrix (T1078.004, T1098.001, T1087.004): https://attack.mitre.org/matrices/enterprise/cloud/
18. NIST SP 800-53 Rev. 5, "Security and Privacy Controls for Information Systems and Organizations": https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
19. Center for Internet Security, "CIS Amazon Web Services Foundations Benchmark": https://www.cisecurity.org/benchmark/amazon_web_services
20. NIST SP 800-61 Rev. 2, "Computer Security Incident Handling Guide": https://csrc.nist.gov/pubs/sp/800/61/r2/final
21. AWS, "Service control policies (SCPs)": https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html
22. AWS, "Validating CloudTrail log file integrity": https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html
23. AWS, "Locking objects with Object Lock": https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html
