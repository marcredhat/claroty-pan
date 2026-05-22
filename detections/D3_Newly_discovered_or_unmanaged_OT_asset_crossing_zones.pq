serverHost='pan-claroty-demo' and dataSource.name contains 'Palo Alto'
| lookup device_type, approved_policy_group, site
    from claroty_assets by ip = src.ip.address
| filter approved_policy_group == 'unassigned'
      or device_type == 'Unknown'
| filter src_zone != dst_zone
| group hits=count()
    by src.ip.address, device_type, site, src_zone, dst_zone
| sort -hits
