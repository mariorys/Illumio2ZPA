# illumio2ZPA

Treat Illumio as source of truth for creating / updating the list of applications in ZPA which are then used to allow access to these applications remotely.
 Applications are created on ZPA based on the scope in a rule with the rule-name in Ilumio as well as applications per “interesting IP List” to allow IP based access – in addition to circumvent the missing DNS resolution of IP addresses forwareded into ZPA tunnel the local AD DNS is dumped and mapped accordingly to the workload and IPL data. 
 
 Additional filtering is applied to remove unwanted FQDN entries before uploading to ZPA to not clutter their "applications"

      0.9  ignore "active FTP highport exclusion rules from 1024-65535" - hardcoded in illumio_api
 
           minor bugfixes
           major speed improvements if we have to retry an IPL update / insert
      
      0.91 optimized service port additions / updates: identify and remove overlaps, convert output to ranges [ port 3301,3302,3303, 2998-3302 -> 2998-3303 ]
 
      0.92 copy the ZPA ruleset as CSV for documentation purposes (only app and SAML attribute)
           add logging to a file
       
      0.93 fixed error checkOverlappingPorts where the last Port in the list was omitted

# illumio2ZPA
Note:

WL: Workload in Illumio
IPL: IP lists in Illumio
 
 This tool heavily relies on proper naming conventions, as example for IPLs would be IPL-CC-SiteName-BusinessUnit[-more granular-identifier]
Side note: naming convention: names are automatically prepended in ZPA
            Illumio workload “IL_”
            Illumio IPL “IPL_”

Script flow

1)	Get WL and IPL data from Illumio
2)	Get data from DNS
3)	Enrich IPLs and workloads with DNS data, respecting filters json config
4)	Get full Illumio ruleset
5)	Parse ruleset according to our filters in json config, looking mainly on extra scope rules matching our filters
6)	Split between “user ports” and “admin ports” (currently the latter being ssh and RDP)
7)	Create / Update applications in Zscaler


Instructions: 

edit config files  
zpa_config.json 
            customer_id
            url
            apiroot (usually “mgmtconfig/”) 
            client_id & client_secret (as per ZPA API config)
            adminConsumers (legycy, to be removed)

and il_config.json 
            api_user / api_key from Illumio API User
            api_node   PCE Hostname
            api_orgid   Illumio ORG ID
            api_protocol  [https| http]
            api_port
            invalidIpRanges IP ranges to ignore / not publish to ZPA – a.e. backup or management networks
            ServiceBySite     treat services per site (for global services spread across site that need to be separated)
            ServiceIgnore     list of Application labels to ignore 
            ZscalerWantedConsumers   list of consumers (IP lists, starting with said strings [IPL-]) to search for in the “consumer” part of extra scope rules in the ruleset
            ZscalerUnwantedConsumers list of consumers (IP lists, starting with said strings [IPL-BackupNetwork]) to ignore for in the “consumer” part of extra scope rules in the ruleset
            adminPorts          ports treated as “for admin access only” – this creates a separate application in ZPA with the appendix “_admin” [3389,22]
            RuleIgnore   ["R-VENDOR-Management"]
            ZscalerUnwantedIP-Pattern       IP Patten to exclude
            IPLCleanUpSite    remove IPLs from creating applications per IP List IPL_RU-%
            IPLCleanUpName remove fqdns from inside applications to not overflow ZPA, mainly for devices that are not used to connect to remotely anyway ["laptop%","desktop%"]
            IPLCleanUpNameRegex regex to remove fqdns from inside applications to not overflow ZPA, mainly for devices that are not used to connect to remotely anyway ":["^[0-9]+.domain.local"]

the dns_config.json file is automatically generated on first launch as it holds the password of a service user that is required to access authenticated LDAP.
