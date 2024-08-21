---
layout:	post
title:  "AD: Fundamentals"
date:   2024-07-15 11:11:11 +0200
categories: [Active Directory]
tags: [Active Directory]
---

***Objects*** are any resource in the network. 

***Directory*** is a herirachy structure that store information about the objects on network. 

***Directory service*** is responsible for storing and providing those information across the network. 

Microsoft have created a set of such directory services for domain-based network which is known as ***Active Directory*** (AD). 

One of the most popular directory service of AD is ***Active Directory Domain Service*** (AD DS). 

The server running the AD DS is known as ***Domain Controller*** (DC). 

The first DC server that gets promoted to AD DS becomes forest by default.

![AD Environment](/images/2024-07-15-AD:Fundamentals/1.png)

<br>

***Forest*** is security boundary and is group of trees.

- Security boundary because all domains within the same forest have by default two-way transitive trust; meaning If domain A trusts domain B and domain B trusts domain C, domain A will automatically trust domain C (covered later).

**Tree** is hierarchical (parent-child) structure of domains that share common namespace. 

***Domain*** is logical group of objects which may contain multiple Organizational Unit (OU) and share an AD database.

***OU*** is container that store similar objects.

<br>

Special roles are assigned to DCs in AD environment known as ***Flexible Single Master Operator*** (FSMO) Roles:

- Schema Master
- Domain Naming Master
- RID Master
- PDC Emulator Master
- Infrastructure Master

![FSMO](/images/2024-07-15-AD:Fundamentals/2.png)


In AD environment, the availability of resource sharing is goverened by trust. ***Trust*** is secure authenticated communication bridge between domain/forest.

Additionally trust can be categorized as following:   

- Based on direction
    - One-way
        - Provide access from trusted domain to trusting domain.
        - Trust direction will be opposite to access direction.

        ![One-way Trust](/images/2024-07-15-AD:Fundamentals/6.png)

    - Two-way
        - Provide access to both trusting partner domain.
        - Both access and trust direction is bi-directional.
- Based on characteristics
    - Transitive
        - Trust extends beyond domain any other domain that trusting partner domain trusts.
    - Non-transitive
        - Trust exist only between two trusting partner domain

<br>

When trust is created, SID filtering is enabled by default. ***SID filtering*** is a security mechanism that filter out any SID from user’s Acces Token that are not part of trusted domain to ensure only SID from trusted domain are used while accessing a resource over a trust.

- If a user is member of five group, it will recieve a SID for each of those five groups. The SID that are not part of trusted domain gets removed by SID filtering when that user try to access resource over a trust.

Whenever user access resource over trust, the user SID will be added to ***Foreign Security Principals***, which is represents security principals from foreign another domain.
