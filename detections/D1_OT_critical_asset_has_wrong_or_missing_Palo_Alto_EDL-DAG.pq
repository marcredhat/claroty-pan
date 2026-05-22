serverHost='pan-claroty-demo' and dataSource.name contains 'Palo Alto'
| lookup device_type, criticality, expected_edl, expected_dag, site
    from claroty_assets by ip = src.ip.address
| filter criticality in ('Critical','High')
| filter src_external_dynamic_list != expected_edl
      or src_dynamic_address_group != expected_dag
| group hits=count()
    by src.ip.address, device_type, criticality, site,
       src_external_dynamic_list, expected_edl,
       src_dynamic_address_group, expected_dag
| sort -hits
