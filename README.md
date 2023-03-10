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
