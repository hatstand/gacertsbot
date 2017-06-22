package gacertsbot

import (
	. "github.com/smartystreets/goconvey/convey"
	"testing"
)

func TestConvert(t *testing.T) {
	Convey("Converts PKCS8 to PKCS1", t, func() {
		pk8 := `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC/od77Re+qs/ur
4oZymCwcs+ON+j0P5DSjQV1r6iMNBiJyeIHoGpmjmKBGOckpK8tdHuZ2Sidc7BEF
fBi5sX0DR0MUgnJQxlO50y7NKM4h69cLkDBqOmAP5BzAvzDShEUOj+iwtnGkOhVo
D1IgTMkoKMrlGQu7ZN1l+DDZGQSb2MFw2jYT/Pf8MT7joIDOv81WTyI7+Ki9D6UY
o4K7/zSGmJNTDKwL3kWfvR073mB8nbm+ag0sGPA1MsX9ybATwUZvfRBesmNjluX2
WcYn912DOZCApFfaxWGtjGjcOLDlF6Z+iiN4zOxEGxbPtYWOp9CYLwdiYqNQJ37m
XZUovZzxAgMBAAECggEAZVIVzq9kj9IH4BKuWYqh0C9AwoGrpWpYdnUKCxPJooo6
zmFu9iSSVVBOdbL57D3OkZbT7Xk5pMTgHxFFFXGFkqUsD30FKjYicJ77INhRXNgQ
ZHnBT3k770sB9Nth2fy7cn6eXkiof1eCl/l5x8Axn30qAcWjUVp8QPzf/vleWXNu
JsWi1pF7QicnGitWqcD7IZ9ayIREGkHp9cOd3JOOlEmDWxlYGsT6/JcKwY7ISrrT
9Ska89afdJRgS3MzHCnTQ1Wt2CgAxvKhb0h4BjWR1rPFI7ruEoH++BbHeSW/WUST
VXO4njhk+acN/V0gmolIJrrrfGCUMXeNnN/fw/l/0QKBgQD+Tx5vc3bZIfmcGNt9
skqe/KqqChljVQ8l94KOb+PSwIGW0OD+TcnkBye/Yco+T+1tmIExwTFUvlbvTxLA
XQbJYLWsKnNaW82wrSx+2oiw9GokTbkKfYsMewU0ybeWN3x80SKFIqs0GyR8WcfR
3xHNcT1arFS4PKKjXqkvkEekbQKBgQDA6BCQHB1YiGo0XowtiDiX4fQ6E+2sTUPK
t8teGyxnEnVZEzSs+w8lHTCMS6ZR7xRiZpNt6evrb/lzUNbv1jG6GIgJ1BXzi+5p
Oy9O1UrbXa0Eo2SRzY3GtnEhpbNFqyV/b8B69LqVA+IH0kq3a1Y/ythkN+Wt440F
SJ2Gwt2gFQKBgQCFH9+70gK+CZYEC9MiiqmbboLcfmrp38YNRvL2I0Zstc9gprmR
BiGQl9pLyiI32llczL+czxhG11jk70zOnCQIWPLhTFuUSohzW0P2p+l0UI4bsQAT
qMKYZvHDv3C2Vxd4s3XRoeNjZG4GFm2OxKoqFIRcqeezhjJROSVxu6J1RQKBgQCB
NO6jF7GwMu6v1QQfGzaMxJNIs0BmP/pANYrJpXnAL+TZnLuTgTVLrplt3t2v02rb
3cixvhR+xalXS7YrPlRgST4VFzD8x6UQZsvxCXvyInRYvvgFkKB9kIWF++5vo4qi
KL/Lm0+9r7QdeQUChapnX/5AYhA8wEUcXN7l/G9lYQKBgCCbAJJ9fgAEY8PBFIq8
MNd6Z/2LpCxZHk9Vdot8p6sPdSGDAYrRxqRI9zGGaec0GadbjfbqK85MEPe+fjA0
9hRyUMSgnkV+80mXNFZFJ0V3cWCXQX8xTmdPr4HgNBmph06okXCs485jg7yxPs4S
qzfNXzRH6loMl9zGajPHhVJ9
-----END PRIVATE KEY-----`
		pkcs1, err := PKCS8ToPKCS1([]byte(pk8))
		So(err, ShouldBeNil)
		So(string(pkcs1), ShouldContainSubstring, "---BEGIN RSA PRIVATE KEY---")
		So(string(pkcs1), ShouldContainSubstring, "---END RSA PRIVATE KEY---")
	})
}
