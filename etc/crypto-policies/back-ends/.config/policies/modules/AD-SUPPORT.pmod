# AD-SUPPORT policy module is intended to be used in Active Directory
# environments where either accounts or trusted domain objects were not yet
# migrated to AES or future encryption types. Active Directory implicitly
# requires RC4 encryption in Kerberos by default.
cipher@kerberos = RC4-128+
hash@kerberos = MD5+
