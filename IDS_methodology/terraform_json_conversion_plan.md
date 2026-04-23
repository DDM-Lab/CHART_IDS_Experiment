# Terraform JSON Conversion Plan for Network Topology

## Purpose
This document defines a structured plan for converting an existing simulation-oriented JSON (e.g., `global_constraints.json`) into a Terraform-compliant JSON configuration. It is designed to guide an LLM in systematically transforming the input into valid Terraform syntax.

---

## Core Principle

**Separate concerns clearly:**
- KEEP: Infrastructure-relevant topology (subnets, hosts, routing intent)
- REMOVE: Simulation logic, IDS constraints, temporal/event-generation rules
- TRANSFORM: Abstract topology → concrete Terraform resources

---

## Step 1: Remove Non-Terraform Sections

Delete the following top-level fields entirely:

- `label_distribution`
- `unsw_grounding_principles`
- `tiered_synthesis_framework`
- `false_alarm_taxonomy`
- `temporal_architecture_principles`
- `validation_checkpoints`
- `output_schema`
- `unsw_dataset_reference`

These are not compatible with Terraform and belong to simulation or data pipelines.

---

## Step 2: Extract Network Topology

From the input JSON, retain only:

- `network_topology.subnets`
- `network_topology.routing_constraints`

Ignore all descriptive text fields except where needed for naming.

---

## Step 3: Introduce Terraform Top-Level Structure

Create the following required top-level blocks:

```json
{
  "terraform": {},
  "provider": {},
  "resource": {},
  "variable": {},
  "locals": {},
  "output": {}
}
```

At minimum, `terraform`, `provider`, and `resource` must be populated.

---

## Step 4: Add Provider Configuration

Insert a provider block (default to AWS unless specified otherwise):

```json
"provider": {
  "aws": {
    "region": "us-east-1"
  }
}
```

---

## Step 5: Create VPC Resource

Define a base VPC (required for subnet placement):

```json
"resource": {
  "aws_vpc": {
    "main": {
      "cidr_block": "10.0.0.0/16"
    }
  }
}
```

---

## Step 6: Convert Subnets

For each subnet in `network_topology.subnets`:

### Required Transformations:

1. Assign a CIDR block (deterministic mapping):
   - subnet_1 → 10.0.1.0/24
   - subnet_2 → 10.0.2.0/24
   - subnet_3 → 10.0.3.0/24

2. Create Terraform resource:

```json
"aws_subnet": {
  "subnet_name": {
    "vpc_id": "${aws_vpc.main.id}",
    "cidr_block": "<assigned_cidr>"
  }
}
```

---

## Step 7: Convert Hosts to Instances

For each host in each subnet:

### Transformation Rules:

- Normalize name: lowercase for resource names (e.g., `User0` → resource name `user0`; hostname remains `User0`)
- Replace invalid characters if needed
- Map to `aws_instance`
- Use **Amazon Linux 2** AMI (region-specific)
- Assign **fixed private IP** (within subnet CIDR)
- Tag instances with role and original hostname

### Private IP Allocation:

- **Subnet 1 (User)**: 10.0.1.10-10.0.1.14 (for User0-User4)
- **Subnet 2 (Enterprise)**: 10.0.2.10-10.0.2.12 (for Enterprise0-2), 10.0.2.20 (Defender)
- **Subnet 3 (Operational)**: 10.0.3.10-10.0.3.12 (for OpHost0-2), 10.0.3.20 (OpServer0)

### Example:

```json
"aws_instance": {
  "user0": {
    "ami": "${data.aws_ami.amazon_linux_2.id}",
    "instance_type": "t2.micro",
    "subnet_id": "${aws_subnet.subnet_user.id}",
    "private_ip": "10.0.1.10",
    "tags": {
      "Name": "User0",
      "role": "user-workstation"
    }
  }
}
```

### Notes:
- Use Amazon Linux 2 AMI (lookup via data source or variable)
- Instance type: `t2.micro` (default, suitable for testing)
- All hosts: fixed private IP assignment
- Instance tags: original hostname + role designation

---

## Step 8: Encode Routing Constraints and Security Groups

Convert routing rules and access control into:

- `aws_internet_gateway` (User subnet internet access)
- `aws_security_group` (intra-subnet and cross-subnet rules)
- `aws_route_table` and `aws_route` (if needed for explicit routing)

### Routing Rules (from specification):

| Source | Destination | Allowed? | Notes |
|--------|-------------|----------|-------|
| Any User host | Internet | ✓ Yes | All users access internet via IGW |
| User1 | Enterprise1 | ✓ Yes | Designated gateway (attack path) |
| Any User (except User1) | Any Enterprise | ✗ No | Restricted to User1 only |
| Enterprise1 | Enterprise2 | ✓ Yes | Cross-enterprise path |
| Any other Enterprise host | Any Operational | ✗ No | Restricted to Enterprise2 only |
| Enterprise2 | OpServer0 | ✓ Yes | Designated operational gateway |
| Within any subnet | Within same subnet | ✓ Yes | All intra-subnet communication allowed |
| Defender (Enterprise) | All Subnets | ✓ Yes | IDS/IPS system: full visibility across network |
| Any other | Any other | ✗ No | Default deny all |

### Security Group Implementation:

1. **sg_user_subnet**: Intra-subnet allow + User1 egress to Enterprise1
2. **sg_enterprise_subnet**: Intra-subnet allow + Enterprise1 ingress from User1 + Enterprise1→Enterprise2 allow + Enterprise2 egress to OpServer0
3. **sg_operational_subnet**: Intra-subnet allow + OpServer0 ingress from Enterprise2
4. **sg_defender**: Intra-subnet allow + ingress from all three subnets (monitoring traffic)
5. **sg_igw_access**: Allow User subnet egress to internet (0.0.0.0/0)

### Example (security group enabling specific cross-subnet path):

```json
"aws_security_group": {
  "sg_user_to_enterprise_gateway": {
    "ingress": [{
      "from_port": 0,
      "to_port": 65535,
      "protocol": "tcp",
      "security_groups": ["${aws_security_group.sg_user_subnet.id}"],
      "description": "Allow User1 to Enterprise1"
    }],
    "egress": [{
      "from_port": 0,
      "to_port": 65535,
      "protocol": "-1",
      "cidr_blocks": ["10.0.0.0/16"],
      "description": "Allow any outbound within VPC"
    }]
  }
}
```

### Internet Gateway Configuration:

```json
"aws_internet_gateway": {
  "main": {
    "vpc_id": "${aws_vpc.main.id}",
    "tags": { "Name": "main-igw" }
  }
},
"aws_route_table": {
  "user_subnet_public": {
    "vpc_id": "${aws_vpc.main.id}",
    "route": [{
      "cidr_block": "0.0.0.0/0",
      "gateway_id": "${aws_internet_gateway.main.id}"
    }]
  }
},
"aws_route_table_association": {
  "user_subnet_public": {
    "subnet_id": "${aws_subnet.subnet_user.id}",
    "route_table_id": "${aws_route_table.user_subnet_public.id}"
  }
}
```

---

## Step 9: IDS/IPS System Configuration

The **Defender** host (in Enterprise subnet) acts as an intrusion detection/prevention system:

### Requirements:
- Located in Subnet 2 (Enterprise) at fixed IP 10.0.2.20
- Has ingress access to **monitor traffic across all three subnets**
- Can receive network traffic from all hosts for analysis
- Tagged as `role: ids-ips-monitor`

### Implementation:
- Security group `sg_defender` allows ingress from all subnets on all ports/protocols
- Defender's security group assigned to `Defender` instance
- No special Terraform resource needed; security group rules handle monitoring access

---

## Step 10: Introduce Variables (Required)

Move reusable values into variables:

- Amazon Linux 2 AMI ID (region-specific lookup)
- Instance type
- Subnet CIDR blocks
- VPC CIDR block

```json
"variable": {
  "aws_region": {
    "type": "string",
    "default": "us-east-1",
    "description": "AWS region for deployment"
  },
  "instance_type": {
    "type": "string",
    "default": "t2.micro",
    "description": "EC2 instance type"
  },
  "vpc_cidr": {
    "type": "string",
    "default": "10.0.0.0/16",
    "description": "VPC CIDR block"
  },
  "subnet_cidrs": {
    "type": "map(string)",
    "default": {
      "user": "10.0.1.0/24",
      "enterprise": "10.0.2.0/24",
      "operational": "10.0.3.0/24"
    }
  }
}
```

### Data Source (Amazon Linux 2 Lookup):

```json
"data": {
  "aws_ami": {
    "amazon_linux_2": {
      "most_recent": true,
      "owners": ["amazon"],
      "filter": [{
        "name": "name",
        "values": ["amzn2-ami-hvm-*-x86_64-gp2"]
      }]
    }
  }
}
```

---

## Step 11: Introduce Locals (Optional)

Use locals to store structured topology mappings and host definitions:

```json
"locals": {
  "subnet_map": {
    "user": "10.0.1.0/24",
    "enterprise": "10.0.2.0/24",
    "operational": "10.0.3.0/24"
  },
  "hosts": {
    "user": {
      "User0": { "ip": "10.0.1.10", "role": "user-workstation" },
      "User1": { "ip": "10.0.1.11", "role": "user-workstation-gateway" },
      "User2": { "ip": "10.0.1.12", "role": "user-workstation" },
      "User3": { "ip": "10.0.1.13", "role": "user-workstation" },
      "User4": { "ip": "10.0.1.14", "role": "user-workstation" }
    },
    "enterprise": {
      "Enterprise0": { "ip": "10.0.2.10", "role": "enterprise-server" },
      "Enterprise1": { "ip": "10.0.2.11", "role": "enterprise-gateway" },
      "Enterprise2": { "ip": "10.0.2.12", "role": "enterprise-gateway" },
      "Defender": { "ip": "10.0.2.20", "role": "ids-ips-monitor" }
    },
    "operational": {
      "OpHost0": { "ip": "10.0.3.10", "role": "operational-server" },
      "OpServer0": { "ip": "10.0.3.20", "role": "operational-server-critical" },
      "OpHost1": { "ip": "10.0.3.11", "role": "operational-server" },
      "OpHost2": { "ip": "10.0.3.12", "role": "operational-server" }
    }
  }
}
```

---

## Step 12: Add Outputs (Recommended)

Expose useful values for verification and integration:

```json
"output": {
  "vpc_id": {
    "value": "${aws_vpc.main.id}",
    "description": "VPC ID"
  },
  "igw_id": {
    "value": "${aws_internet_gateway.main.id}",
    "description": "Internet Gateway ID"
  },
  "user_subnet_id": {
    "value": "${aws_subnet.subnet_user.id}",
    "description": "User Workstations Subnet ID"
  },
  "enterprise_subnet_id": {
    "value": "${aws_subnet.subnet_enterprise.id}",
    "description": "Enterprise Services Subnet ID"
  },
  "operational_subnet_id": {
    "value": "${aws_subnet.subnet_operational.id}",
    "description": "Operational Technology Subnet ID"
  },
  "defender_instance_id": {
    "value": "${aws_instance.defender.id}",
    "description": "Defender (IDS/IPS) Instance ID"
  },
  "user1_instance_id": {
    "value": "${aws_instance.user1.id}",
    "description": "User1 (Gateway) Instance ID"
  },
  "all_instance_ips": {
    "value": {
      "user": "${jsonencode(aws_instance.user0.private_ip, aws_instance.user1.private_ip, ...)}",
      "enterprise": "${jsonencode(aws_instance.enterprise0.private_ip, ...)}",
      "operational": "${jsonencode(aws_instance.ophost0.private_ip, ...)}"
    },
    "description": "All instance private IPs by subnet"
  }
}
```

---

## Step 14: Validation Rules for Output JSON

The generated Terraform JSON must:

1. Contain valid top-level Terraform keys
2. Use only supported Terraform resource types
3. Ensure all references use interpolation syntax:
   - `${resource_type.name.attribute}`
4. Ensure no leftover simulation-only fields remain
5. Ensure all resources have required fields

---

## Step 15: Non-Goals (Explicitly Exclude)

Do NOT attempt to encode:

- IDS logic
- Event sequencing
- Temporal constraints
- Statistical distributions
- Dataset references

These belong outside Terraform.

---

## Step 16: Final Output Expectations

The LLM should output:

- A single valid Terraform JSON file
- Fully self-contained
- Ready to run with `terraform init` and `terraform plan`

---

## Optional Extension (Advanced)

If desired, the LLM may also:

- Tag instances with roles (user, enterprise, operational)
- Add security group segmentation between subnets
- Introduce NAT gateways or internet gateways

---

## Finalized Network Specifications (User-Confirmed)

This section documents all user-confirmed specifications that have been incorporated into the conversion plan:

### Infrastructure Choices:
- **Cloud Provider**: AWS
- **Region**: us-east-1
- **OS**: Amazon Linux 2 across all hosts
- **Instance Type**: t2.micro (test/lab environment)
- **IP Assignment**: Fixed (static) private IPs for all hosts
- **Internet Access**: Direct Internet Gateway (IGW)

### Network Topology:
- **VPC CIDR**: 10.0.0.0/16
- **Subnet 1 (User)**: 10.0.1.0/24 — 5 workstations + internet access
- **Subnet 2 (Enterprise)**: 10.0.2.0/24 — 3 servers + 1 IDS/IPS monitor
- **Subnet 3 (Operational)**: 10.0.3.0/24 — 3 operational hosts + 1 critical server

### Cross-Subnet Access Rules (Strictly Enforced):
1. **User1 → Enterprise1**: Designated attack entry gateway
2. **Enterprise1 ↔ Enterprise2**: Internal enterprise transition
3. **Enterprise2 → OpServer0**: Designated operational gateway
4. **Defender (IDS/IPS)**: Full visibility across all three subnets for monitoring
5. **All intra-subnet**: Hosts within same subnet can communicate freely
6. **All User hosts → Internet**: IGW provides outbound access
7. **All other cross-subnet paths**: Explicitly blocked

### Attack Simulation Model:
- Attacker external to AWS enters via User1 (internet access)
- Follows path: User1 → Enterprise1 → Enterprise2 → OpServer0
- Defender monitors all traffic across all subnets to detect/prevent attack progression
- IDS pipeline generates events representing detection/blocking activity

### Instance Naming & Tagging:
- Resource names: lowercase (e.g., `user0`, `enterprise1`, `defender`)
- Display names: Original case-sensitive hostnames in tags (e.g., "User0", "Enterprise1")
- Role tags: `user-workstation`, `enterprise-server`, `ids-ips-monitor`, `operational-server`, etc.

---

## Summary

Transformation pipeline:

1. Strip simulation logic
2. Extract topology
3. Add Terraform structure
4. Map subnets → aws_subnet
5. Map hosts → aws_instance
6. Encode routing → networking resources
7. Validate Terraform compliance

---

End of specification.

