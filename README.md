Private ENV CLI (click based):
-----------------------------



To Install package
~~~~~~~~~~~~~~~~~~
1. Please clone it: git clone https://github.com/sivanbecker/penv
2. Install from local repo: <pip install -e ...>

Package includes LDAP and TMUX stuff.  once the package was installed using pip ( package name =
penv), you can run the next commands:

- p dhcpldap --username < > --password <> --lab <if different from Infi1> ldap_to_yml --raw --ofile
  <path to output file>
- p dhcpldap --username < > --password <> --lab <if different from Infi1> sanity_report --ofile <if
left empty ,report will be printed to screen>
- p dhcpldap --username < > --password <> ldap_search <string to search>
