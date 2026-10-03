package pwn

import "testing"

func TestPwn(t *testing.T) {
	str := "30:F6:EF:FB:08:29"
	mac, _ := ParseMac(str)
	py := CreatePayloadArray(0, mac, mac, 1234)
	t.Logf("%+v", py)
	/*val := VerifyDoCheckClient(py, mac, 1234, mac)
	println(val)*/
}
