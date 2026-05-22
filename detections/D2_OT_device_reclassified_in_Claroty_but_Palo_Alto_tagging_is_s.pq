serverHost='pan-claroty-demo' and dataSource.name contains 'Palo Alto'
| lookup device_type, expected_dag, hostname, site
    from claroty_assets by ip = src.ip.address
| filter device_type != null
      and device_type != 'Decommissioned'
      and device_type != 'Unknown'
| filter src_dynamic_address_group != expected_dag
| group hits=count()
    by src.ip.address, hostname, device_type, site,
       src_dynamic_address_group, expected_dag
| sort -hits
