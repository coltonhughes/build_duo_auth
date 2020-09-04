# Module Documentation
This module is quite simple.
It provides an easy way to generate Authorization/Date headers for the DUO security API.

# NOTE
This is currently specific to my use cases for DUO Admin API.. Im open to forking/opening issues to broaden the scope of this collection
## Example
```
- name: Generate Authorization/Date Headers
  build_duo_auth::
    integration_key: <integration_key_from_duo_app>
    api_host: api-xxxxxxxx.duosecurity.com
    secret: <secret_from_duo_app>
    method: "GET"
    path: "/admin/v1/users"
    params:
      username: johndoe
```
This is a very simple module that I put very little effort in perfecting.  If issues arise feel free to open them or fork and modify at your own discretion.