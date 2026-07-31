## LDAP with GSSAPI

### Requirements

- Valid credentials for the default domain (username/password).

- Trust relationship between the default domain and the target domain (required for cross-domain LDAP queries).

- Properly configured DNS resolution for SRV records (_ldap._tcp and _kerberos._tcp).

Note: If target domain == default domain then everything works as described below with the exception that in the
Kerberos configuration
we only need one realm/domain of course.

### Example Setup

#### Default Credentials:

- Domain/Realm (default) for which we have credentials: sub.domain.tld
- User: test_user
- Password: test_password

```
"ldap": {
"domain": "sub.domain.tld",
"user": "test_user",
"password": "test_password"
},
```
#### Scan Target

If we have a scan target as `host123.sales.example.org`, then inside hostLookupAd,
host or searchCN is `host123` and ldapAddress or targetDomain is `sales.example.org`

The call to ldapConnectGssapi is then as follows:
```
ldapConnectGssapi(logger, ldapAddress, ldapPort, ldapDomain, ldapUser, ldapPassword, dialTimeout)

with values:
    ldapAddress:sales.example.org // target domain/realm
    ldapPort: 389
    ldapDomain: sub.domain.tld // default domain/realm
    ldapUser: test_user
    ldapPassword: test_password
```

#### Resolve Service Principal Name (SPN)

We must discover an LDAP service endpoint from the target domain.
- SPN = LDAP SRV record of a domain controller.

Therefore:

`spn=cache.GetDc(logger, ldapAddress)`

In command line you can check up if the system is able to find those service records:
```
nslookup -type=srv _ldap._tcp.dc._msdcs.<domain>

example:
nslookup -type=srv _ldap._tcp.dc._msdcs.sales.example.org
```

For better chances of a successfull setup, out of the found results we try to prefer one that supports `StartTLS`
Operation.
In this case for example we found: `dc01.sales.example.org` so we set it as our `spn`.

We connect to `ldap://<spn>:389`

#### Build Kerberos Configuration

Then before we can build a gssapi client, we have to programmatically build the kerberos configuration:

```
// Prepare Kerberos config
krb5Config := buildKrb5Config(logger, defaultRealm, ldapAddress)
```
In this scenario we have two different realms:

- sub.domain.tld as default
- sales.example.org as target

We try to lookup records for KDCs of both realms and append them to our config, if we are not able to setup the right
KDCs, gssapi will
fail. (Example: could not get valid TGT for client's realm: client krb5 config does not have any defined KDCs for the
default realm)

In command line you can check up if the system is able to find the KDCs of a domain with this command:

```
nslookup -type=SRV _kerberos._tcp.<domain>

example:
nslookup -type=SRV _kerberos._tcp.sales.example.org
```

```
// Lookup kdcs for the default realm
kdcs, _ := cache.GetKdc(logger, defaultRealm)

	// Set config realms
	krb5Conf.Realms = append(krb5Conf.Realms, config.Realm{
		Realm:         defaultRealm,
		KDC:           kdcs,
		DefaultDomain: realmDomain,
	})
	
...

// Add a second realm configuration if target domain differs from default realm
if targetRealm != "" && targetRealm != defaultRealm {

		// Lookup key distribution centers for the target realm
		targetKDCs, _ := cache.GetKdc(logger, targetRealm)

		// Update config realm
		krb5Conf.Realms = append(krb5Conf.Realms, config.Realm{
			Realm:         targetRealm,
			KDC:           targetKDCs,
			DefaultDomain: strings.ToLower(targetRealm),
		})
		...
	}
```

#### Create Kerberos Client

With the Kerberos configuration in place we are able to build the gssapi Client with the provided credentials

```
	// Prepare Kerberos client
	krbClient := client.NewWithPassword(
		ldapUser,
		defaultRealm,
		ldapPassword,
		krb5Config,
		client.DisablePAFXFAST(true),
	)
```

#### Bind with GSSAPI

```
// Bind using GSSAPI with mutual authentication
errBind := conn.GSSAPIBindRequestWithAPOptions(gssapiClient, &ldap.GSSAPIBindRequest{
ServicePrincipalName: fmt.Sprintf("ldap/%s", spn),
AuthZID:              "",
}, []int{flags.APOptionMutualRequired})
```

#### Perform LDAP Queries

On that created connection we can then perform the ldap search:

```
// Execute search
computerResult, errComputerSearch := conn.Search(computerSearch)
```