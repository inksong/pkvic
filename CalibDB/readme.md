### CalibDB

You can find CalibDB in https://ieee-dataport.org/documents/calibdb

CalibDB is a database collected and organized by the PKVIC tool, 
which is part of the work of paper "Supplement Missing Software Package Information in Security Vulnerability Reports"

#### Instructions: 

CalibDB contains organized vulnerability report mappings from the following sources: 

`BugTraq, Cisco Security Advisory, DSquare Security, Exploit-DB, Gentoo Linux Security Advisory, Mandrake Linux Security Advisory, Microsoft Security Advisory, OSVDB, RedHat Security Advisory, SUSE Update Advisories, Ubuntu Security Notices, VMware Security Advisories, VulDB` and sorted `CVE, CPE, CWE` mapping relationships.

Considering SecurityTracker's end-of-life, we used the original locally archived vulnerability security report for research purposes only, and no related associations are included in this database.

CalibDB also contains the affected software IDs with or without CVE vulnerability IDs and the corresponding ecosystem information for the 6 software ecosystems(Pypi, Maven, Gem, NPM, Packagist, Nuget) that have been verified using PKVIC.

PKVIC a framework to automatically fill in the missing information between vulnerability reports and software packages of open-source ecosystems.

Using this framework has good performance in calibrating CVEs for mislabeling and missing package references.