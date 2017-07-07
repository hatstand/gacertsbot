package main

import (
	. "github.com/smartystreets/goconvey/convey"
	"testing"
	"time"
)

func TestExtractBlocks(t *testing.T) {
	Convey("Extracts PEM blocks", t, func() {
		pem := `-----BEGIN CERTIFICATE-----
MIIFwjCCBKqgAwIBAgISAyVWW//VNH0GYU04ZRcAoqj2MA0GCSqGSIb3DQEBCwUA
MEoxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MSMwIQYDVQQD
ExpMZXQncyBFbmNyeXB0IEF1dGhvcml0eSBYMzAeFw0xNzA2MjIwMjU5MDBaFw0x
NzA5MjAwMjU5MDBaMCAxHjAcBgNVBAMTFWNsZW1lbnRpbmUtcGxheWVyLm9yZzCC
ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOUMRt2Ehf5xmrje3dMlFGbu
F9sQSLqtUVDty4s7lmD2Q3IEtk8tefeKLrpFFOQsHzAuREezoO+P8ox0+Yke2Il7
ZhhmKOCw90+a+Slpi/3gu+ulgxW3J6rcDbtyf6GNMFHko6E0wp7Nm5SQUgQB8HT1
mBNOCpfwgmhWkWh9RnITZoqKNVRMoam+rn2uMy5glP6uGwP+weIpRKXI7Hk7vJnA
34RRiJP3oWBmK5QHwbQI9CL+8elV1ex1xBI2tsEhRXbc8rBjCiNsl2DwcD+Ocwqd
YZ5pbyKzqNU4nVFZ1j8QT7DBVSZn17twy8+p5sb7sjwEqaOc+SmdXyuKc+EpQCUC
AwEAAaOCAsowggLGMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcD
AQYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUY5BHgxu+V63dyfv3
9FYwIqiubMYwHwYDVR0jBBgwFoAUqEpqYwR93brm0Tm3pkVl7/Oo7KEwbwYIKwYB
BQUHAQEEYzBhMC4GCCsGAQUFBzABhiJodHRwOi8vb2NzcC5pbnQteDMubGV0c2Vu
Y3J5cHQub3JnMC8GCCsGAQUFBzAChiNodHRwOi8vY2VydC5pbnQteDMubGV0c2Vu
Y3J5cHQub3JnLzCB1AYDVR0RBIHMMIHJgh5idWlsZGJvdC5jbGVtZW50aW5lLXBs
YXllci5vcmeCHGJ1aWxkcy5jbGVtZW50aW5lLXBsYXllci5vcmeCFWNsZW1lbnRp
bmUtcGxheWVyLm9yZ4IaZGF0YS5jbGVtZW50aW5lLXBsYXllci5vcmeCHGltYWdl
cy5jbGVtZW50aW5lLXBsYXllci5vcmeCHXNwb3RpZnkuY2xlbWVudGluZS1wbGF5
ZXIub3Jnghl3d3cuY2xlbWVudGluZS1wbGF5ZXIub3JnMIH+BgNVHSAEgfYwgfMw
CAYGZ4EMAQIBMIHmBgsrBgEEAYLfEwEBATCB1jAmBggrBgEFBQcCARYaaHR0cDov
L2Nwcy5sZXRzZW5jcnlwdC5vcmcwgasGCCsGAQUFBwICMIGeDIGbVGhpcyBDZXJ0
aWZpY2F0ZSBtYXkgb25seSBiZSByZWxpZWQgdXBvbiBieSBSZWx5aW5nIFBhcnRp
ZXMgYW5kIG9ubHkgaW4gYWNjb3JkYW5jZSB3aXRoIHRoZSBDZXJ0aWZpY2F0ZSBQ
b2xpY3kgZm91bmQgYXQgaHR0cHM6Ly9sZXRzZW5jcnlwdC5vcmcvcmVwb3NpdG9y
eS8wDQYJKoZIhvcNAQELBQADggEBAEHFZeNbNLv5pfea+dnCwSHMVycOT1RP5hqa
TJQbYtOx5JeqqNGZwCboFylNU41WvgIyXGSjqqkjTEsOfXO4XMw2uvPPXue67498
8MCLkmddUtz2B1FXd5BhTPo/RnEwXO+u64KBGZCqeb+hv+qfRFC8Eeim59EoCapf
O38SovjlXTun+i7HY8BHzDuXRZT0JH45CHqv6VDEdOi3nDTo/JcW7DKDmi+K9LV5
acVrDzugQozl3jBWPBsleRGZjtcHh6Fr6/SuiYwgHPxJYPgEVL9o3yPXW3tpYxgL
6LLnrY5qjsaRv2kXG5aZ9i9SqtFDQsb+TI4rBKq07dapQZcvJP4=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIEkjCCA3qgAwIBAgIQCgFBQgAAAVOFc2oLheynCDANBgkqhkiG9w0BAQsFADA/
MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT
DkRTVCBSb290IENBIFgzMB4XDTE2MDMxNzE2NDA0NloXDTIxMDMxNzE2NDA0Nlow
SjELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUxldCdzIEVuY3J5cHQxIzAhBgNVBAMT
GkxldCdzIEVuY3J5cHQgQXV0aG9yaXR5IFgzMIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEAnNMM8FrlLke3cl03g7NoYzDq1zUmGSXhvb418XCSL7e4S0EF
q6meNQhY7LEqxGiHC6PjdeTm86dicbp5gWAf15Gan/PQeGdxyGkOlZHP/uaZ6WA8
SMx+yk13EiSdRxta67nsHjcAHJyse6cF6s5K671B5TaYucv9bTyWaN8jKkKQDIZ0
Z8h/pZq4UmEUEz9l6YKHy9v6Dlb2honzhT+Xhq+w3Brvaw2VFn3EK6BlspkENnWA
a6xK8xuQSXgvopZPKiAlKQTGdMDQMc2PMTiVFrqoM7hD8bEfwzB/onkxEz0tNvjj
/PIzark5McWvxI0NHWQWM6r6hCm21AvA2H3DkwIDAQABo4IBfTCCAXkwEgYDVR0T
AQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwfwYIKwYBBQUHAQEEczBxMDIG
CCsGAQUFBzABhiZodHRwOi8vaXNyZy50cnVzdGlkLm9jc3AuaWRlbnRydXN0LmNv
bTA7BggrBgEFBQcwAoYvaHR0cDovL2FwcHMuaWRlbnRydXN0LmNvbS9yb290cy9k
c3Ryb290Y2F4My5wN2MwHwYDVR0jBBgwFoAUxKexpHsscfrb4UuQdf/EFWCFiRAw
VAYDVR0gBE0wSzAIBgZngQwBAgEwPwYLKwYBBAGC3xMBAQEwMDAuBggrBgEFBQcC
ARYiaHR0cDovL2Nwcy5yb290LXgxLmxldHNlbmNyeXB0Lm9yZzA8BgNVHR8ENTAz
MDGgL6AthitodHRwOi8vY3JsLmlkZW50cnVzdC5jb20vRFNUUk9PVENBWDNDUkwu
Y3JsMB0GA1UdDgQWBBSoSmpjBH3duubRObemRWXv86jsoTANBgkqhkiG9w0BAQsF
AAOCAQEA3TPXEfNjWDjdGBX7CVW+dla5cEilaUcne8IkCJLxWh9KEik3JHRRHGJo
uM2VcGfl96S8TihRzZvoroed6ti6WqEBmtzw3Wodatg+VyOeph4EYpr/1wXKtx8/
wApIvJSwtmVi4MFU5aMqrSDE6ea73Mj2tcMyo5jMd6jmeWUHK8so/joWUoHOUgwu
X4Po1QYz+3dszkDqMp4fklxBwXRsW10KXzPMTZ+sOPAveyxindmjkW8lGy+QsRlG
PfZ+G6Z6h7mjem0Y+iWlkYcV4PIWL1iwBi8saCbGS5jN2p8M+X+Q7UNKEkROb3N6
KOqkqm57TH2H3eDJAkSnh6/DNFu0Qg==
-----END CERTIFICATE-----`
		Convey("Extracts PEM blocks correctly", func() {
			So(extractBlocks([]byte(pem)), ShouldNotBeEmpty)
		})

		Convey("Extracts expiry time", func() {
			expiry, err := extractExpiry([]byte(pem), "clementine-player.org")
			So(expiry, ShouldHappenAfter, time.Unix(0, 0))
			So(err, ShouldBeNil)
		})

		Convey("Fails to extract expiry for missing domain", func() {
			expiry, err := extractExpiry([]byte(pem), "foobar.com")
			So(expiry, ShouldHappenOnOrBefore, time.Unix(0, 0))
			So(err, ShouldNotBeNil)
		})
	})
}