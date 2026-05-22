serverHost='pan-claroty-demo' and dataSource.name contains 'Palo Alto'
| lookup device_type, claroty_risk, approved_policy_group, site, zone
    from claroty_assets by ip = src.ip.address
| filter device_type != null
| filter claroty_risk >= '80'
| filter dst_zone in ('IT-CORP','INTERNET','DMZ','GUEST')
| group hits=count()
    by src.ip.address, device_type, claroty_risk, site,
       src_zone, dst_zone, application
| sort -hits
