# Cilium Blocked DNS Resolution

## Goal

The purpose of this ADS is to detect when Cilium blocks DNS requests originating from pods in the Rubix environment.

## Categorization

These attempts are categorized as [Command and Control](https://attack.mitre.org/tactics/TA0011/) / [Application Layer Protocol: DNS](https://attack.mitre.org/techniques/T1071/004/)

## Environments

* Palantir Rubix

## Platforms

* Self-Hosted Applications
* SAAS Applications
* Kubernetes

## Tooling

* Cilium

## Technical Context

### Rubix
Rubix is a cloud platform that runs alongside the Palantir Cloud to securely run Foundry workers and executors in containers on Kubernetes; Rubix is a more secure and scalable solution that Palantir developed to replace Palantir Cloud Jails.

Some of Rubix's most notable differences with existing Palantir Cloud Jails:

* Spark and other RCE workloads run in a Palantir-secured Kubernetes cluster, which provides container sandboxing from the underlying hosts and network isolation between individual Spark modules.
* RCE workloads are further isolated by running in a separate VPC with only front door access back to the Palantir Cloud. This significantly reduces the risk and blast radius of a malicious Foundry RCE workload.
* SSH onto Rubix hosts is only available for break glass circumstances. It is not available to administrators in steady state. Rubix intentionally limits the use and availability of SSH in order to minimize the attack surface for each cluster.
* Each host in a Rubix environment is destroyed and rebuilt every 40-72 hours. The primary benefit for doing this is it greatly reduces the risk of persistent threats, as an attacker will need to re-compromise a host every time it is prebuilt. This additionally introduces a baseline amount of entropy into the environment that will allow us to be more confident in our platform’s ability to survive isolated failure.

Rubix provides the ability to dynamically scale the resources available for Foundry workloads, up to the maximum configured by a deployment for that instance group. For example, an instance group used by Spark jobs can dynamically scale from 10 nodes under low utilization up to 20 or 50 or 100+ nodes when demand is at its peak.

### Cilium & Hubble
[Cilium](https://cilium.io/) is open-source software used in the Rubix environment for securing the network connectivity between application services deployed using Linux container management platforms like Docker and Kubernetes.

Cilium supports DNS-based network controls that only allow for the resolution of domains specified in the DNS egress policy. Rubix stacks use DNS-based security policies to disallow traffic to any domains not specified in that stack's egress configuration policy.

[Hubble](https://docs.cilium.io/en/v1.9/intro/#what-is-hubble) is the observability / logging platform built on top of Cilium; it uses [eBPF](https://ebpf.io/) to achieve visibility into the operations occurring on an endpoint, and in turn generates discrete log entries for a variety of events.

**Palantir's SIEM currently ingests Cilium / Hubble's network flow events, and process events; the following log entry shows an example of a network flow event in which Cilium drops traffic to a desetination whose domain isn't on the allow list:**

```
{ [-]
   flow: { [-]
     IP: { [-]
       destination: 10.0.X.X
       ipVersion: IPv4
       source: 10.0.X.X
     }
     Summary: DNS Query XXXXXXXX.windows.net. AAAA
     Type: L7
     destination: { [-]
       identity: 2
       labels: [ [-]
         reserved:world
       ]
     }
     event_type: { [-]
       type: 129
     }
     l4: { [-]
       UDP: { [-]
         destination_port: 8053
         source_port: 43086
       }
     }
     l7: { [-]
       dns: { [-]
         observation_source: proxy
         qtypes: [ [-]
           AAAA
         ]
         query: XXXXXXXX.windows.net.
       }
       type: REQUEST
     }
     node_name: XXXXXXXX
     source: { [-]
       ID: 2321
       identity: 29085
       labels: [ [-]
         k8s:com.palantir.deployability.ingress-manager.pod/service=spark-module-0e49dd1f90564bda844af9131dcc6e048772
         k8s:io.cilium.k8s.namespace.labels.name=smm-0e49dd1f90564bda844af9131dcc6e048772
         k8s:io.cilium.k8s.namespace.labels.spark-backend-id=0e49dd1f-9056-4bda-844a-f9131dcc6e04-8772
         k8s:io.cilium.k8s.namespace.labels.spark-module-id=0e49dd1f-9056-4bda-844a-f9131dcc6e04
         k8s:io.cilium.k8s.namespace.labels.spark-module-type=python-1
         k8s:io.cilium.k8s.policy.cluster=default
         k8s:io.cilium.k8s.policy.serviceaccount=default
         k8s:io.kubernetes.pod.namespace=smm-0e49dd1f90564bda844af9131dcc6e048772
         k8s:is-driver-pod=true
         k8s:spark-app-id=0e49dd1f-9056-4bda-844a-f9131dcc6e04
         k8s:spark-app-selector=spark-b39e6245b12d493f9bc4375508ef1a29
         k8s:spark-module-id=0e49dd1f-9056-4bda-844a-f9131dcc6e04
         k8s:spark-role=driver
       ]
       namespace: smm-0e49dd1f90564bda844af9131dcc6e048772
       pod_name: python1-0e49dd1f-9056-4bda-844a-f9131dcc6e04-1619652123324-driver
     }
     time: 2021-04-28T23:25:57.893023190Z
     verdict: DROPPED
   }
   node_name: XXXXXXXX
   time: 2021-04-28T23:25:57.893023190Z
}
```
### Rubix Egress Configurations
Each Rubix stack maintains a `security.yml` file that contains the allowed egress IP addresses, URLs, and domains.  In addition to the stack-specific allowed egress, there are globally-allowed egress IPs, URLs, and domains that are applied to every stack. The globally-allowed egress values are for cloud service infrastructure, and internal Palantir infrastructure. Cilium collects the egress details from the stack's `security.yml` file and generates corresponding rules in real-time.

## Strategy Abstract

This alerting & detection strategy will function as follows:

* Hubble logs will be ingested into our SIEM for all Rubix stacks.
* A scheduled Splunk query will identify blocked DNS requests by searching for `cilium:v2:flow_dns` events with `flow.verdict"=DROPPED`.
* Blocked domains will be evaluated against an allowed-list.
	* Events for blocked domains in the allowed-list will be suppressed. 
* Blocked domains that are not in the allowed-list will generate an alert. 

## Blind Spots and Assumptions

### Blind Spots:

A blind spot may occur under the following circumstances:

* Cilium / Hubble telemetry is not correctly logged and ingested into our SIEM.
* A previously approved domain name is utilized for Command & Control.
* An adversary is able to leverage advanced capabilities to bypass DNS security policies, such as [Domain Fronting](https://attack.mitre.org/techniques/T1090/004) using an approved domain.

### Assumptions:

This strategy relies on the following assumptions:

*  Cilium / Hubble telemetry is correctly logged and ingested into our SIEM.
* A known-good domain name has not been repurposed for malicious command & control communication.

## False Positives

The following events will result in a false positive:

* If a known good domain hasn't yet been added to a stack's `security.yml` file, this alert may fire when Rubix resources attempt to resolve that domain.

## Validation

To validate this ADS:

* Request a member of the Rubix team use break-glass access and authenticate to a Rubix host.
* The break-glass activity above will trigger its own separate InfoSec alert; please let the rest of the team know why the activity is occurring.
* Have the Rubix personnel Perform a domain name query for a domain not included in the allowed list using nslookup, dig, or an equivalent tool.
* Run the ADS's search query against the timeframe of the activity.
* Validate that the activity resulted in a true-positive event for the ADS.

## Alert Priority

This alert is set to **Medium** priority under all circumstances.

## Response

In the event that this alert fires, the following response procedures are recommended:

* Identify the domain name indicated in the failed DNS request.
* Use the following questions to determine the context of the event:
    * What does open-source intelligence suggest about the domain name?
    * Has it been used to distribute malware in the past?
    * How long has it been in use?
    * What are the domain registration details?
* Identify historical traffic to the suspect domain name; is this infrastructure historically known to us?
	* It's possible that the domain is allowed in other network security controls, but just hasn't been added to the Rubix stack's configurations yet.
* The Cilium / Hubble events used in this alert contain a label `k8s:io.cilium.k8s.namespace.labels.spark-module-id` that records the Spark module ID responsible for the alert.  We can attribute the activity to a specific Spark module, and Foundry user using the Spark module ID.
	* Ex. `k8s:io.cilium.k8s.namespace.labels.spark-module-id=87b0ccfc-f89c-4319-935e-56be1a3d6b56`
* If the initial triage steps listed above don't yield answers that explain the alert, escalate to an investigation.

## Additional Resources

* [Cilium Documentation](https://docs.cilium.io/)
* [Kubernetes Documentation](https://kubernetes.io/docs/home/)
* [Introducing Rubix](https://blog.palantir.com/introducing-rubix-kubernetes-at-palantir-ab0ce16ea42e)
