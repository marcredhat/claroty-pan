serverHost='pan-claroty-demo' and dataSource.name contains 'Palo Alto'
| lookup device_type, criticality
    from claroty_assets by ip = src.ip.address
| filter device_type == 'Decommissioned' or criticality == 'None'
| filter src_external_dynamic_list != ''
      and src_external_dynamic_list != 'unknown'
| group hits=count()
    by src.ip.address, device_type, criticality,
       src_external_dynamic_list, src_dynamic_address_group
