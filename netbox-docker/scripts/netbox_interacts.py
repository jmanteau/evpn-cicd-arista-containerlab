from dcim.models import Device, Site
from extras.scripts import *

class Create_ASN(Script):
    class Meta:
        name = "ex Create autonomous system numbers"
        description = "Create autonomous system numbers"
        field_order = ['site','device']

    site=ObjectVar(
        description="select a site",
        model=Site,
        default=None,
        required=True,
        query_params={
            'side_id': '$site'
        }
    )

    device=ObjectVar(
        description="select a device",
        model=Device,
        default=None,
        required=True,
        query_params={
            'device_id':'$device'
        }
    )
    def run(self,data,commit):
        return ''

class job(Script):
    class Meta:
        name = "ex Create "
        description = "build "
        field_order = ['site','device']

    site=ObjectVar(
        description="select a site",
        model=Site,
        default=None,
        required=True,
        query_params={
            'side_id': '$site'
        }
    )

    device=ObjectVar(
        description="select a device",
        model=Device,
        default=None,
        required=True,
        query_params={
            'device_id':'$device'
        }
    )
    def run(self,data,commit):
        return ''
