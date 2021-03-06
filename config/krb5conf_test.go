package config

import (
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"os"
	"testing"
	"time"
)

const (
	krb5Conf = `
[logging]
 default = FILE:/var/log/kerberos/krb5libs.log
 kdc = FILE:/var/log/kerberos/krb5kdc.log
 admin_server = FILE:/var/log/kerberos/kadmind.log

[libdefaults]
 default_realm = TEST.GOKRB5
 dns_lookup_realm = false

 dns_lookup_kdc = false
 #dns_lookup_kdc = true
 ;dns_lookup_kdc = true
#dns_lookup_kdc = true
;dns_lookup_kdc = true
 ticket_lifetime = 10h
 forwardable = yes
 default_keytab_name = FILE:/etc/krb5.keytab

 default_client_keytab_name = FILE:/home/gokrb5/client.keytab
 default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96


[realms]
 TEST.GOKRB5 = {
  kdc = 10.80.88.88:88
  kdc = assume.port.num
  kdc = some.other.port:1234

  kdc = 10.80.88.88*
  kdc = 10.1.2.3.4:88

  admin_server = 10.80.88.88:749
  default_domain = test.gokrb5
 }
 EXAMPLE.COM = {
        kdc = kerberos.example.com
        kdc = kerberos-1.example.com
        admin_server = kerberos.example.com
        auth_to_local = RULE:[1:$1@$0](.*@EXAMPLE.COM)s/.*//
 }


[domain_realm]
 .test.gokrb5 = TEST.GOKRB5

 test.gokrb5 = TEST.GOKRB5

[appdefaults]
 pam = {
   debug = false

   ticket_lifetime = 36000

   renew_lifetime = 36000
   forwardable = true
   krb4_convert = false
 }
`
	krb5Conf2 = `
[logging]
 default = FILE:/var/log/kerberos/krb5libs.log
 kdc = FILE:/var/log/kerberos/krb5kdc.log
 admin_server = FILE:/var/log/kerberos/kadmind.log

[libdefaults]
 default_realm = TEST.GOKRB5
 dns_lookup_realm = false

 dns_lookup_kdc = false
 #dns_lookup_kdc = true
 ;dns_lookup_kdc = true
#dns_lookup_kdc = true
;dns_lookup_kdc = true
 ticket_lifetime = 10h
 forwardable = yes
 default_keytab_name = FILE:/etc/krb5.keytab

 default_client_keytab_name = FILE:/home/gokrb5/client.keytab
 default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96

[domain_realm]
 .test.gokrb5 = TEST.GOKRB5

 test.gokrb5 = TEST.GOKRB5

[appdefaults]
 pam = {
   debug = false

   ticket_lifetime = 36000

   renew_lifetime = 36000
   forwardable = true
   krb4_convert = false
 }
 [realms]
 TEST.GOKRB5 = {
  kdc = 10.80.88.88:88
  kdc = assume.port.num
  kdc = some.other.port:1234

  kdc = 10.80.88.88*
  kdc = 10.1.2.3.4:88

  admin_server = 10.80.88.88:749
  default_domain = test.gokrb5
 }
 EXAMPLE.COM = {
        kdc = kerberos.example.com
        kdc = kerberos-1.example.com
        admin_server = kerberos.example.com
 }
`
)

func TestLoad(t *testing.T) {
	cf, _ := ioutil.TempFile(os.TempDir(), "TEST-gokrb5-krb5.conf")
	defer os.Remove(cf.Name())
	cf.WriteString(krb5Conf)

	c, err := Load(cf.Name())
	if err != nil {
		t.Fatalf("Error loading config: %v", err)
	}

	assert.Equal(t, "TEST.GOKRB5", c.LibDefaults.DefaultRealm, "[libdefaults] default_realm not as expected")
	assert.Equal(t, false, c.LibDefaults.DNSLookupRealm, "[libdefaults] dns_lookup_realm not as expected")
	assert.Equal(t, false, c.LibDefaults.DNSLookupKDC, "[libdefaults] dns_lookup_kdc not as expected")
	assert.Equal(t, time.Duration(10)*time.Hour, c.LibDefaults.TicketLifetime, "[libdefaults] Ticket lifetime not as expected")
	assert.Equal(t, true, c.LibDefaults.Forwardable, "[libdefaults] forwardable not as expected")
	assert.Equal(t, "FILE:/etc/krb5.keytab", c.LibDefaults.DefaultKeytabName, "[libdefaults] default_keytab_name not as expected")
	assert.Equal(t, "FILE:/home/gokrb5/client.keytab", c.LibDefaults.DefaultClientKeytabName, "[libdefaults] default_client_keytab_name not as expected")
	assert.Equal(t, []string{"aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96"}, c.LibDefaults.DefaultTktEnctypes, "[libdefaults] default_tkt_enctypes not as expected")

	assert.Equal(t, 2, len(c.Realms), "Number of realms not as expected")
	assert.Equal(t, "TEST.GOKRB5", c.Realms[0].Realm, "[realm] realm name not as expectd")
	assert.Equal(t, []string{"10.80.88.88:749"}, c.Realms[0].AdminServer, "[realm] Admin_server not as expectd")
	assert.Equal(t, []string{"10.80.88.88:464"}, c.Realms[0].KPasswdServer, "[realm] Kpasswd_server not as expectd")
	assert.Equal(t, "test.gokrb5", c.Realms[0].DefaultDomain, "[realm] Default_domain not as expectd")
	assert.Equal(t, []string{"10.80.88.88:88", "assume.port.num:88", "some.other.port:1234", "10.80.88.88:88"}, c.Realms[0].KDC, "[realm] Kdc not as expectd")
	assert.Equal(t, []string{"kerberos.example.com:88", "kerberos-1.example.com:88"}, c.Realms[1].KDC, "[realm] Kdc not as expectd")
	assert.Equal(t, []string{"kerberos.example.com"}, c.Realms[1].AdminServer, "[realm] Admin_server not as expectd")

	assert.Equal(t, "TEST.GOKRB5", c.DomainRealm[".test.gokrb5"], "Domain to realm mapping not as expected")
	assert.Equal(t, "TEST.GOKRB5", c.DomainRealm["test.gokrb5"], "Domain to realm mapping not as expected")

}

func TestLoad2(t *testing.T) {
	c, err := NewConfigFromString(krb5Conf2)
	if err != nil {
		t.Fatalf("Error loading config: %v", err)
	}

	assert.Equal(t, "TEST.GOKRB5", c.LibDefaults.DefaultRealm, "[libdefaults] default_realm not as expected")
	assert.Equal(t, false, c.LibDefaults.DNSLookupRealm, "[libdefaults] dns_lookup_realm not as expected")
	assert.Equal(t, false, c.LibDefaults.DNSLookupKDC, "[libdefaults] dns_lookup_kdc not as expected")
	assert.Equal(t, time.Duration(10)*time.Hour, c.LibDefaults.TicketLifetime, "[libdefaults] Ticket lifetime not as expected")
	assert.Equal(t, true, c.LibDefaults.Forwardable, "[libdefaults] forwardable not as expected")
	assert.Equal(t, "FILE:/etc/krb5.keytab", c.LibDefaults.DefaultKeytabName, "[libdefaults] default_keytab_name not as expected")
	assert.Equal(t, "FILE:/home/gokrb5/client.keytab", c.LibDefaults.DefaultClientKeytabName, "[libdefaults] default_client_keytab_name not as expected")
	assert.Equal(t, []string{"aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96"}, c.LibDefaults.DefaultTktEnctypes, "[libdefaults] default_tkt_enctypes not as expected")

	assert.Equal(t, 2, len(c.Realms), "Number of realms not as expected")
	assert.Equal(t, "TEST.GOKRB5", c.Realms[0].Realm, "[realm] realm name not as expectd")
	assert.Equal(t, []string{"10.80.88.88:749"}, c.Realms[0].AdminServer, "[realm] Admin_server not as expectd")
	assert.Equal(t, []string{"10.80.88.88:464"}, c.Realms[0].KPasswdServer, "[realm] Kpasswd_server not as expectd")
	assert.Equal(t, "test.gokrb5", c.Realms[0].DefaultDomain, "[realm] Default_domain not as expectd")
	assert.Equal(t, []string{"10.80.88.88:88", "assume.port.num:88", "some.other.port:1234", "10.80.88.88:88"}, c.Realms[0].KDC, "[realm] Kdc not as expectd")
	assert.Equal(t, []string{"kerberos.example.com:88", "kerberos-1.example.com:88"}, c.Realms[1].KDC, "[realm] Kdc not as expectd")
	assert.Equal(t, []string{"kerberos.example.com"}, c.Realms[1].AdminServer, "[realm] Admin_server not as expectd")

	assert.Equal(t, "TEST.GOKRB5", c.DomainRealm[".test.gokrb5"], "Domain to realm mapping not as expected")
	assert.Equal(t, "TEST.GOKRB5", c.DomainRealm["test.gokrb5"], "Domain to realm mapping not as expected")

}

func TestParseDuration(t *testing.T) {
	// https://web.mit.edu/kerberos/krb5-1.12/doc/basic/date_format.html#duration
	hms, _ := time.ParseDuration("12h30m15s")
	hm, _ := time.ParseDuration("12h30m")
	h, _ := time.ParseDuration("12h")
	var tests = []struct {
		timeStr  string
		duration time.Duration
	}{
		{"100", time.Duration(100) * time.Second},
		{"12:30", hm},
		{"12:30:15", hms},
		{"1d12h30m15s", time.Duration(24)*time.Hour + hms},
		{"1d12h30m", time.Duration(24)*time.Hour + hm},
		{"1d12h", time.Duration(24)*time.Hour + h},
		{"1d", time.Duration(24) * time.Hour},
	}
	for _, test := range tests {
		d, err := parseDuration(test.timeStr)
		if err != nil {
			t.Errorf("Error parsing %s: %v", test.timeStr, err)
		}
		assert.Equal(t, test.duration, d, "Duration not as expected for: "+test.timeStr)

	}

}
