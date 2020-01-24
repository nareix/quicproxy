package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/gob"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	quic "github.com/lucas-clemente/quic-go"
)

var qconfig = &quic.Config{
	KeepAlive: true,
}

func main() {
	log.Fatal(proxy())
}

type Handshake struct {
	ID string
}

type RequestProxy struct {
	ID   string
	Addr string
}

type Proxy struct {
	Addr string
}

var (
	id          = flag.String("id", "", "id")
	qlistenaddr = flag.String("ql", "", "quic listen addr")
	qhostaddr   = flag.String("qh", "", "quic host addr")
)

func init() {
	gob.Register(Handshake{})
	gob.Register(RequestProxy{})
	gob.Register(Proxy{})
}

func proxy() error {
	flag.Parse()

	if *id == "" {
		return fmt.Errorf("need id")
	}

	if *qlistenaddr != "" {
		return quicServer()
	} else if *qhostaddr != "" {
		return quicClient()
	} else {
		return fmt.Errorf("must be quic server or client")
	}
}

func quicServer() error {
	ql, err := quic.ListenAddr(*qlistenaddr, generateTLSConfig(), qconfig)
	if err != nil {
		return err
	}

	var allsess sync.Map

	handleStream := func(sess quic.Session, stream quic.Stream) {
		defer stream.Close()

		log.Println(sess.RemoteAddr(), stream.StreamID(), "stream accpeted")
		defer log.Println(sess.RemoteAddr(), stream.StreamID(), "stream closed")

		r := gob.NewDecoder(stream)
		reqproxy := RequestProxy{}
		if err := r.Decode(&reqproxy); err != nil {
			log.Println(sess.RemoteAddr(), stream.StreamID(), "stream decode failed:", err)
			return
		}
		log.Println(sess.RemoteAddr(), stream.StreamID(), "stream request proxy", proxy)

		targetsess0, ok := allsess.Load(reqproxy.ID)
		if !ok {
			log.Println(sess.RemoteAddr(), stream.StreamID(), "target sess not found")
			return
		}

		targetsess := targetsess0.(quic.Session)
		targetstream, err := targetsess.OpenStream()
		if err != nil {
			log.Println(targetsess.RemoteAddr(), "open stream failed:", err)
			return
		}
		defer targetstream.Close()

		w := gob.NewEncoder(targetstream)
		if err := w.Encode(Proxy{Addr: reqproxy.Addr}); err != nil {
			log.Println(targetsess.RemoteAddr(), targetstream.StreamID(), "write failed:", err)
			return
		}

		log.Println(
			sess.RemoteAddr(), stream.StreamID(), "->", targetsess.RemoteAddr(), targetstream.StreamID(),
			"start proxy", proxy,
		)

		ch := make(chan interface{}, 2)
		go func() {
			io.Copy(stream, targetstream)
			ch <- nil
		}()
		go func() {
			io.Copy(targetstream, stream)
			ch <- nil
		}()
		<-ch
	}

	handleSess := func(sess quic.Session) {
		defer sess.Close()

		log.Println(sess.RemoteAddr(), "accepted")
		defer log.Println(sess.RemoteAddr(), "closed")

		hsstream, err := sess.AcceptStream(context.Background())
		if err != nil {
			log.Println(sess.RemoteAddr(), "handshake failed:", err)
			return
		}
		defer hsstream.Close()

		r := gob.NewDecoder(hsstream)
		hs := Handshake{}
		if err := r.Decode(&hs); err != nil {
			log.Println(sess.RemoteAddr(), "handshake decode failed:", err)
			return
		}
		log.Println(sess.RemoteAddr(), "handshake ok", "id", hs.ID)

		_, exist := allsess.LoadOrStore(hs.ID, sess)
		if exist {
			log.Println(sess.RemoteAddr(), "id exists")
			return
		}
		defer allsess.Delete(hs.ID)

		for {
			stream, err := sess.AcceptStream(context.Background())
			if err != nil {
				log.Println(sess.RemoteAddr(), "accept stream failed:", err)
				return
			}
			go handleStream(sess, stream)
		}
	}

	log.Println("quic listen", *qlistenaddr)

	for {
		sess, err := ql.Accept(context.Background())
		if err != nil {
			return err
		}
		go handleSess(sess)
	}
}

func quicClient() error {
	for {
		err := quicClientSession()
		if err != nil {
			log.Println("quicClientSession:", err)
		}
		time.Sleep(time.Second)
	}
}

func quicClientSession() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"quic-echo-example"},
	}
	sess, err := quic.DialAddrContext(ctx, *qhostaddr, tlsConf, qconfig)
	if err != nil {
		return err
	}
	defer sess.Close()

	hsstream, err := sess.OpenStream()
	if err != nil {
		return err
	}
	defer hsstream.Close()

	w := gob.NewEncoder(hsstream)
	if err := w.Encode(Handshake{*id}); err != nil {
		return err
	}

	log.Println(sess.RemoteAddr(), "handshake ok")

	handleStream := func(sess quic.Session, stream quic.Stream) {
		defer stream.Close()

		log.Println(sess.RemoteAddr(), stream.StreamID(), "stream accpeted")
		defer log.Println(sess.RemoteAddr(), stream.StreamID(), "stream closed")

		r := gob.NewDecoder(stream)
		proxy := Proxy{}
		if err := r.Decode(&proxy); err != nil {
			log.Println(sess.RemoteAddr(), stream.StreamID(), "stream decode failed:", err)
			return
		}
		log.Println(sess.RemoteAddr(), stream.StreamID(), "stream proxy", proxy)

		d := net.Dialer{}
		targetstream, err := d.DialContext(ctx, "tcp", proxy.Addr)
		if err != nil {
			log.Println(sess.RemoteAddr(), stream.StreamID(), "dial", proxy.Addr, "failed:", err)
			return
		}
		defer targetstream.Close()

		log.Println(
			sess.RemoteAddr(), stream.StreamID(), "->", targetstream.RemoteAddr(),
			"start proxy", proxy,
		)

		ch := make(chan interface{}, 2)
		go func() {
			io.Copy(stream, targetstream)
			ch <- nil
		}()
		go func() {
			io.Copy(targetstream, stream)
			ch <- nil
		}()
		<-ch
	}

	go func() {
		defer cancel()
		for {
			stream, err := sess.AcceptStream(ctx)
			if err != nil {
				log.Println(sess.RemoteAddr(), "accept failed:", err)
				os.Exit(1)
				return
			}
			go handleStream(sess, stream)
		}
	}()

	handleConn := func(nc net.Conn, targetid, targetaddr string) {
		log.Println(nc.RemoteAddr(), "accepted")
		defer nc.Close()

		defer log.Println(sess.RemoteAddr(), nc.RemoteAddr(), "closed")

		stream, err := sess.OpenStream()
		if err != nil {
			log.Println(sess.RemoteAddr(), nc.RemoteAddr(), "open remote stream failed:", err)
			return
		}
		defer stream.Close()

		w := gob.NewEncoder(stream)
		if err := w.Encode(RequestProxy{ID: targetid, Addr: targetaddr}); err != nil {
			log.Println(sess.RemoteAddr(), nc.RemoteAddr(), "remote stream write failed:", err)
			return
		}

		log.Println(
			sess.RemoteAddr(), stream.StreamID(), "<->", nc.RemoteAddr(),
			"start proxy",
		)

		ch := make(chan interface{}, 2)
		go func() {
			io.Copy(nc, stream)
			ch <- nil
		}()
		go func() {
			io.Copy(stream, nc)
			ch <- nil
		}()
		<-ch
	}

	handleLocalListen := func(pair string) {
		seg := strings.Split(pair, ",")
		localaddr := seg[0]
		targetid := seg[1]
		targetaddr := seg[2]

		var lc net.ListenConfig
		l, err := lc.Listen(ctx, "tcp", localaddr)
		if err != nil {
			log.Println("listen", localaddr, "failed")
			return
		}
		log.Println("listen", localaddr, "proxy", targetid, targetaddr)

		for {
			nc, err := l.Accept()
			if err != nil {
				return
			}
			go handleConn(nc, targetid, targetaddr)
		}
	}

	for _, pair := range flag.Args() {
		go handleLocalListen(pair)
	}

	<-ctx.Done()
	return nil
}

// Setup a bare-bones TLS config for the server
func generateTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"quic-echo-example"},
	}
}
