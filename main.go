package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/big"
	"runtime/debug"
	"sync"

	"io"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"
)

type SmartCardReader struct {
	Name       string `json:"name"`
	CardStatus uint16 `json:"cardstatus"`
}

type SmartCardReadersResponse struct {
	Readers     *[]SmartCardReader `json:"readers"`
	ErrorDetail uint16             `json:"errordetail"`
	ErrorCode   uint16             `json:"errorcode"`
}

type ApduCommand struct {
	Apdu string `json:"apdu"`
}

type ApduRequest struct {
	Timeout      uint16         `json:"timeout"`
	Apducommands *[]ApduCommand `json:"apducommands"`
	Session      string         `json:"session"`
}

type InnerApduResponse struct {
	Apdu string `json:"apdu"`
}

type ApduResponse struct {
	Apduresponses []InnerApduResponse `json:"apduresponses"`
	Errordetail   int16               `json:"errordetail"`
	Errorcode     int16               `json:"errorcode"`
}

type DisconnectRequest struct {
	Session string `json:"session"`
}

type VersionResponse struct {
	Version string `json:"version"`
}

type RefResponse struct {
	Ref  int64  `json:"ref"`
	Data string `json:"data"`
}

type refKey struct {
	key       []byte
	createdAt time.Time
}

type smartCardSession struct {
	session string
	reader  string
	context *scContext
	handle  *scHandle
	tx      *scTx
}

func (session *smartCardSession) Close() error {
	err1 := session.tx.Close()
	err2 := session.handle.Close()
	err3 := session.context.Close()
	if err1 == nil {
		if err2 == nil {
			return err3
		}
		return err2
	}
	return err1
}

var currentSmartcardSession *smartCardSession

var knownReaders = make([]string, 0)

var knownKeys = make(map[int64]refKey)

var scMutex = &sync.Mutex{}

func logError(msg string, err error, r *http.Request) {
	slog.Error(msg, "err", err, "path", r.URL.Path, "method", r.Method)
}

func returnJson(w http.ResponseWriter, data interface{}) {
	jsonResp, err := json.Marshal(data)
	if err != nil {
		slog.Error("error marshalling json", "err", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonResp)
}

func handleCors(w http.ResponseWriter, r *http.Request) bool {

	origin := r.Header.Get("Origin")
	if !strings.HasPrefix(origin, "https://secure.") || !strings.HasSuffix(origin, ".buypass.no") {
		slog.Warn("Rejecting request from invalid origin", "origin", origin, "path", r.URL.Path, "method", r.Method)
		w.WriteHeader(http.StatusForbidden)
		return false
	}

	// Why do we not need private-access here?
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Access-Control-Allow-Methods", "POST")
	return true
}

func tryReadBodyIntoStruct(w http.ResponseWriter, r *http.Request, data any) bool {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		logError("Error reading body", err, r)
		w.WriteHeader(http.StatusBadRequest)
		return false
	}

	err = json.Unmarshal(body, &data)
	if err != nil {
		logError("Failed to unmarshal json", err, r)
		w.WriteHeader(http.StatusBadRequest)
		return false
	}
	return true
}

func deObscurifyPinApdu(apdu []byte, knownKeys map[int64]refKey) ([]byte, error) {
	if len(apdu) < 3 || apdu[0] != 0xFF || apdu[1] != 0xFF {
		slog.Debug("Non-obscurified apdu", "apdu", apdu)
		return apdu, nil
	}

	reader := bytes.NewReader(apdu[2:])

	keyRefLengthLength, err := reader.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("failed to read key ref length length %s", err)
	}

	if keyRefLengthLength != 1 {
		return nil, fmt.Errorf("unexpected key ref length length %d", keyRefLengthLength)
	}

	keyReferenceLength, err := reader.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("obscurified pin command too short")
	}

	keyReference := make([]byte, keyReferenceLength)
	byteCount, err := reader.Read(keyReference)
	if err != nil || byteCount != int(keyReferenceLength) {
		return nil, fmt.Errorf("obscurified pin command too short")
	}

	cmdLen, err := reader.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("failed to read cmd length %s", err)
	}

	pinLen, err := reader.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("failed to read pin length %s", err)
	}

	cmd := make([]byte, cmdLen)
	byteCount, err = reader.Read(cmd)
	if err != nil || byteCount != int(cmdLen) {
		return nil, fmt.Errorf("failed to read cmd")
	}

	pin := make([]byte, pinLen)
	byteCount, err = reader.Read(pin)
	if err != nil || byteCount != int(pinLen) {
		return nil, fmt.Errorf("failed to read pin")
	}

	rest, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to ending of obscurified pin command: %s", err)
	}

	keyData, ok := knownKeys[new(big.Int).SetBytes(keyReference).Int64()]
	if !ok {
		return nil, fmt.Errorf("unknown key reference: %s", hex.EncodeToString(keyReference))
	}

	for i := 0; i < len(pin); i++ {
		pin[i] = pin[i] ^ keyData.key[i] ^ keyData.key[i+len(pin)]
	}

	slog.Debug("de obscurificated pin", "key_ref", keyReference, "cmd_len",
		cmdLen, "pin_len", pinLen, "cmd", cmd, "pin", pin, "rest", rest,
	)

	return slices.Concat(cmd, pin, rest), nil
}

func getSession(session string, reader string) (*smartCardSession, error) {
	if currentSmartcardSession != nil && currentSmartcardSession.session == session && currentSmartcardSession.reader == reader {
		slog.Debug("Reusing existing session", "session", session, "reader", reader)
		return currentSmartcardSession, nil
	}

	if currentSmartcardSession != nil {
		slog.Debug("Superseding session", "session", currentSmartcardSession.session, "reade", currentSmartcardSession.reader)
		err := currentSmartcardSession.Close()
		if err != nil {
			slog.Warn("Error closing existing session",
				"error", err, "session", currentSmartcardSession.session,
				"reader", currentSmartcardSession.reader)
		}
	}

	scContext, err := newSCContext()
	if err != nil {
		return nil, fmt.Errorf("error creating context: %w", err)
	}

	handle, err := scContext.Connect(reader)
	if err != nil {
		return nil, fmt.Errorf("error connecting to reader: %w", err)
	}

	tx, err := handle.Begin()
	if err != nil {
		return nil, fmt.Errorf("error beginning transaction: %w", err)
	}

	slog.Debug("Created new tx", "session", session, "reader", reader)
	currentSmartcardSession = &smartCardSession{session, reader, scContext, handle, tx}
	go cleanUpSession(session, reader)
	return currentSmartcardSession, nil
}

func cleanUpSession(session string, reader string) {
	time.Sleep(10 * time.Second)

	scMutex.Lock()
	defer scMutex.Unlock()

	slog.Debug("Checking that session is cleaned up", "session", session, "reader", reader)
	if currentSmartcardSession != nil && currentSmartcardSession.session == session && currentSmartcardSession.reader == reader {
		slog.Warn("Cleaning up dangling session", "session", session, "reader", reader)
		err := currentSmartcardSession.Close()
		if err != nil {
			slog.Error("Error closing session", "error", err, "session", session, "reader", reader)
		}
		currentSmartcardSession = nil
	}
}

func handleApdu(w http.ResponseWriter, r *http.Request) {
	if !handleCors(w, r) {
		return
	}

	scMutex.Lock()
	defer scMutex.Unlock()

	var apduRequest ApduRequest
	if !tryReadBodyIntoStruct(w, r, &apduRequest) {
		return
	}

	reader := r.PathValue("reader")

	if !slices.Contains(knownReaders, reader) {
		slog.Warn("Reader not recognized", "reader", reader)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	session, err := getSession(apduRequest.Session, reader)
	if err != nil {
		slog.Error("Error getting session", "error", err, "session", apduRequest.Session, "reader", reader)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	var tx = session.tx

	apduResponses := make([]InnerApduResponse, 0)
	var errordetail int16 = 0
	for _, apduCommand := range *apduRequest.Apducommands {

		apduData, err := hex.DecodeString(apduCommand.Apdu)
		if err != nil {
			slog.Error("Error decoding apdu", "err", err, "apdu", apduCommand.Apdu)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		apduData, err = deObscurifyPinApdu(apduData, knownKeys)
		if err != nil {
			slog.Error("Error deobscurifying pin apdu", "err", err, "apdu", apduCommand.Apdu)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		resp, err := tx.Transmit(apduData)
		if err != nil {
			var e *apduErr
			if errors.As(err, &e) {
				resp = []byte{e.sw1, e.sw2}
				slog.Debug("error transmitting apdu", "err", err)
			} else {
				slog.Warn("error transmitting apdu", "err", err)
			}
			errordetail = -3
		}

		apduResponses = append(apduResponses, InnerApduResponse{hex.EncodeToString(resp)})

	}
	returnJson(w, ApduResponse{apduResponses, errordetail, 0})
}

func handleDisconnect(w http.ResponseWriter, r *http.Request) {
	if !handleCors(w, r) {
		return
	}

	scMutex.Lock()
	defer scMutex.Unlock()

	var disconnectRequest DisconnectRequest
	if !tryReadBodyIntoStruct(w, r, &disconnectRequest) {
		return
	}

	if currentSmartcardSession != nil && currentSmartcardSession.session == disconnectRequest.Session {
		err := currentSmartcardSession.Close()
		if err != nil {
			slog.Error("Error closing session", "error", err, "session", disconnectRequest.Session)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		currentSmartcardSession = nil
	} else {
		slog.Debug("No session to close for disconnect request", "session", disconnectRequest.Session)
	}

}

func listReaders(w http.ResponseWriter, r *http.Request) {
	if !handleCors(w, r) {
		return
	}

	scMutex.Lock()
	defer scMutex.Unlock()

	scContext, err := newSCContext()
	if err != nil {
		slog.Error("Error creating context", "err", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer scContext.Close()

	readers, err := scContext.ListReaders()
	if err != nil {
		slog.Error("Error listing readers", "err", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	smartCardReaders := make([]SmartCardReader, 0)
	for _, reader := range readers {
		if !slices.Contains(knownReaders, reader) {
			knownReaders = append(knownReaders, reader)
		}

		handle, err := scContext.Connect(reader)
		var status uint16 = 302
		if err != nil {
			var e *scErr
			if errors.As(err, &e) && e.rc == 0x8010000C {
				// No smartcard in the reader
				status = 303
			} else {
				status = 304
			}
			slog.Info("Error connecting to reader", "error", err, "reader", reader)
		}
		if handle != nil {
			handle.Close()
		}
		smartCardReaders = append(smartCardReaders, SmartCardReader{reader, status})
	}

	returnJson(w, SmartCardReadersResponse{&smartCardReaders, 0, 0})
}

func handleVersion(w http.ResponseWriter, r *http.Request) {
	if !handleCors(w, r) {
		return
	}
	// We have "feature parity" with the Buypass 1.5.2 version.
	returnJson(w, VersionResponse{"1.5.2"})
}

func getRefHandler(w http.ResponseWriter, r *http.Request) {
	if !handleCors(w, r) {
		return
	}

	// (don't try to make sense of this max number)
	ref, err := rand.Int(rand.Reader, big.NewInt(3983487934))
	if err != nil {
		slog.Error("Error generating random number", "err", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	data := make([]byte, 16)

	_, err = rand.Read(data)
	if err != nil {
		slog.Error("Error generating random data", "err", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if len(knownKeys) > 10 {
		oldestRef := int64(0)
		oldestTime := time.Now()
		for refKey, key := range knownKeys {
			if key.createdAt.Before(oldestTime) {
				oldestTime = key.createdAt
				oldestRef = refKey
			}
		}
		slog.Debug("Cleaning up ref", "ref", oldestRef, "createdAt", oldestTime)
		delete(knownKeys, oldestRef)
	}

	knownKeys[ref.Int64()] = refKey{key: data, createdAt: time.Now()}

	returnJson(w, RefResponse{ref.Int64(), hex.EncodeToString(data)})
}

func handlePreflight(w http.ResponseWriter, r *http.Request) {
	if !handleCors(w, r) {
		return
	}
	w.WriteHeader(http.StatusOK)
}

func handleRoot(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("You have successfully reached the SC proxy"))
	w.WriteHeader(http.StatusOK)
}

func getVersionInfo() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "Unknown"
	}
	return fmt.Sprintf("%s (%s)", info.Main.Version, info.GoVersion)
}

func main() {

	var (
		installFlag     = flag.Bool("install", false, "")
		uninstallFlag   = flag.Bool("uninstall", false, "")
		skipServiceFlag = flag.Bool("skip-service", false, "")
		debugFlag       = flag.Bool("debug", false, "")
		versionFlag     = flag.Bool("version", false, "")
	)
	flag.Parse()
	if *versionFlag {
		fmt.Printf("%s\n", getVersionInfo())
		return
	}

	if *installFlag {
		install(*skipServiceFlag)
		return
	}
	if *uninstallFlag {
		uninstall()
		return
	}

	if *debugFlag {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}

	http.HandleFunc("GET /", handleRoot)
	http.HandleFunc("POST /scard/version/", handleVersion)
	http.HandleFunc("POST /scard/list/", listReaders)
	http.HandleFunc("POST /scard/apdu/{reader}", handleApdu)
	http.HandleFunc("POST /scard/disconnect/", handleDisconnect)
	http.HandleFunc("POST /scard/getref/", getRefHandler)
	http.HandleFunc("OPTIONS /", handlePreflight)

	certPath, keyPath, err := getCertAndKeyPathAndValidate()
	if err != nil {
		log.Fatalf("Did not find TLS certificate and key. Have you run --install? Error: %s\n", err)
	}

	slog.Info("Starting SC proxy", "version", getVersionInfo())

	err = http.ListenAndServeTLS("127.0.0.1:31505", certPath, keyPath, nil)
	if errors.Is(err, http.ErrServerClosed) {
		fmt.Printf("server closed\n")
	} else if err != nil {
		fmt.Printf("error starting server: %s\n", err)
		os.Exit(1)
	}
}
