package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"runtime"
	"runtime/pprof"
	"time"

	"github.com/beeemT/Packages/netutil"
	sha256 "github.com/minio/sha256-simd"
	rand "gitlab.com/NebulousLabs/fastrand"

	"github.com/beeemT/Packages/sc"
)

var (
	remotePort    int
	remoteAddr    net.IP
	email                = ""
	firstName            = ""
	lastName             = ""
	projectChoice uint16 = 7071
	teamNumber    uint16
)

const (
	protoEnrollInit     uint16 = 680
	protoEnrollRegister uint16 = 681
	protoEnrollSuccess  uint16 = 682
	protoEnrollFailure  uint16 = 683
)

type errorSpecifiedSize struct {
	protoMsg                 uint16
	expectedSize, actualSize int64
}

type errorReceivedMsgType struct {
	expectedMsgType, actualMsgType uint16
}

func (e errorSpecifiedSize) Error() string {
	return fmt.Sprintf("%d provided %d as size. Expected %d.", e.protoMsg, e.actualSize, e.expectedSize)
}

func (e errorReceivedMsgType) Error() string {
	return fmt.Sprintf("Expected msgType %d but received a msg of type %d.", e.expectedMsgType, e.actualMsgType)
}

func calcMsgWithNonce(msg []byte, payload []byte) []byte {
	resChan := make(chan []byte, 1)
	ctrlChan := make(chan struct{})
	defer close(resChan)

	c := 0
	t := time.Now()
	for index := 0; index < runtime.NumCPU(); index++ {
		go func(retChan chan []byte, ctrlChan chan struct{}, msg, payload []byte) {
			h := sha256.New()

			//now follows some slice magic
			data := make([]byte, len(msg)+len(payload)+8)
			copy(data[0:len(msg)], msg)
			copy(data[len(msg)+8:], payload)
			nonceData := data[len(msg) : len(msg)+8]

			for {
				select {
				//close routines bc other routine already found a result
				case <-ctrlChan:
					runtime.Goexit()
				default:
					rand.Read(nonceData)

					h.Write(data)
					sum := h.Sum(nil)
					c++
					if sum[0] == 0 && sum[1] == 0 && sum[2] == 0 && sum[3] == 0 {
						dur := time.Since(t)
						log.Println("Hashing Rate: ", float64(c)/dur.Seconds())
						log.Printf("Hash: %s", fmt.Sprintln(sum))
						retChan <- data
						runtime.Goexit()
					}
					h.Reset()
				}
			}
		}(resChan, ctrlChan, msg, payload)
	}
	ret := <-resChan

	//send shutdown signal
	close(ctrlChan)
	return ret
}

func readMsg(conn *sc.Conn) (*bytes.Buffer, error) {
	buf := bytes.NewBuffer(make([]byte, 0, 512))
	//read size
	_, err := io.CopyN(buf, conn, 2)
	if err != nil {
		return nil, err
	}

	size := int64(binary.BigEndian.Uint16(buf.Next(2))) - 2

	//read rest of msg. (size - 2 bytes)
	_, err = io.CopyN(buf, conn, size)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

func handleEnrollInit(conn *sc.Conn) ([]byte, error) {
	enrollInitBuf, err := readMsg(conn)
	if err != nil {
		log.Fatalf("%s\n", err.Error())
	}
	log.Printf("Received Init Message...\n")

	if enrollInitBuf.Len() != 10 {
		return nil, errorSpecifiedSize{protoMsg: protoEnrollInit, expectedSize: 12, actualSize: int64(enrollInitBuf.Len() + 2)}
	}

	msgType := binary.BigEndian.Uint16(enrollInitBuf.Next(2))
	challenge := enrollInitBuf.Next(8)

	if msgType != protoEnrollInit {
		return nil, errorReceivedMsgType{expectedMsgType: protoEnrollInit, actualMsgType: msgType}
	}
	log.Printf("Processed Init Message.\n")
	log.Printf("Challenge: %s", fmt.Sprintln(challenge))
	return challenge, nil
}

func handleEnrollRegister(conn *sc.Conn, challenge []byte) error {
	msgBuf := bytes.NewBuffer(make([]byte, 0, 512))
	headerBuf := bytes.NewBuffer(make([]byte, 0, 512))

	payload := fmt.Sprintf("%s\r\n%s\r\n%s", email, firstName, lastName)
	binary.Write(msgBuf, binary.BigEndian, challenge)
	binary.Write(msgBuf, binary.BigEndian, teamNumber)
	binary.Write(msgBuf, binary.BigEndian, projectChoice)

	log.Printf("Starting hashing on [%d] routines...\n", runtime.NumCPU())
	msg := calcMsgWithNonce(msgBuf.Bytes(), []byte(payload))

	binary.Write(headerBuf, binary.BigEndian, uint16(len(msg)+4))
	binary.Write(headerBuf, binary.BigEndian, protoEnrollRegister)

	_, err := headerBuf.Write(msg)
	if err != nil {
		return err
	}

	log.Println("Challenge: ", challenge)
	log.Println("Register Message: ", headerBuf.Bytes())

	return nil
	//n, err := io.Copy(conn, headerBuf)
	//log.Printf("Processed Register. Written %d bytes.", n)
	//return err
}

func handleEnrollResponse(conn *sc.Conn) error {
	enrollRespBuf, err := readMsg(conn)
	if err != nil {
		return err
	}

	msgType := binary.BigEndian.Uint16(enrollRespBuf.Next(2))
	if msgType == protoEnrollSuccess {
		if enrollRespBuf.Len() != 4 {
			return errorSpecifiedSize{protoMsg: protoEnrollSuccess, expectedSize: 8, actualSize: int64(enrollRespBuf.Len() + 4)}
		}

		enrollRespBuf.Next(2)
		recTeamNumber := binary.BigEndian.Uint16(enrollRespBuf.Next(2))
		log.Printf("Success. Teamnumber: %d\n", recTeamNumber)

	} else if msgType == protoEnrollFailure {
		enrollRespBuf.Next(2)
		errNum := binary.BigEndian.Uint16(enrollRespBuf.Next(2))
		errDesc := string(enrollRespBuf.Bytes())
		log.Printf("Failure. Errornumber: %d\nErrDesc: %s\n", errNum, errDesc)

	} else {
		return errorReceivedMsgType{expectedMsgType: protoEnrollSuccess, actualMsgType: msgType}
	}
	return nil
}

func handle(conn *sc.Conn, a ...interface{}) {
	log.Println("Handling Init...")
	challenge, err := handleEnrollInit(conn)
	if err != nil {
		log.Fatalf("%s\n", err.Error())
	}

	log.Println("Handling Register...")
	err = handleEnrollRegister(conn, challenge)
	if err != nil {
		log.Fatalf("%s\n", err.Error())
	}
	conn.Close()
	return

	log.Println("Handling Response...")
	err = handleEnrollResponse(conn)
	if err != nil {
		log.Fatalf("%s\n", err.Error())
	}
}

func main() {
	remoteAddrP := flag.String("remoteAddr", "fulcrum.net.in.tum.de", "Specifies the remote addr that the client connects to.")
	remotePortP := flag.Int("remotePort", 34151, "Specifies the remote port that the client connects to.")

	flag.Parse()

	if *remoteAddrP == "" {
		log.Fatalf("remoteAddr is empty. Please provide a valid address.\n")
		flag.Usage()
		runtime.Goexit()
	}
	remoteAddrList, err := net.LookupHost(*remoteAddrP)
	if err != nil {
		log.Fatalf("%s\n", err.Error())
		runtime.Goexit()
	}

	remoteAddr, err := netutil.IP(remoteAddrList[0])
	if err != nil {
		log.Fatalf("%s\n", err.Error())
		flag.Usage()
		runtime.Goexit()
	}

	remotePort = *remotePortP
	if remotePort < 0 || remotePort > 65535 {
		log.Fatalf("Port out of range. Please provide a port within range.\n")
		flag.Usage()
		runtime.Goexit()
	}

	f, err := os.Create("/home/bt/go/benchmark/Enrollclient")
	if err != nil {
		log.Fatal(err)
	}
	pprof.StartCPUProfile(f)
	defer pprof.StopCPUProfile()

	c := sc.NewClient(remoteAddr, remotePort, 0, 0)
	wG := c.Connect(handle)
	wG.Wait()
}
