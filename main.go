package main

import (
    "fmt"
    "github.com/bronze1man/radius"
)

type radiusService struct{}

func (p radiusService) RadiusHandle(request *radius.Packet) *radius.Packet {
    // a pretty print of the request.
    fmt.Printf("[Authenticate] %s\n", request.String())
    npac := request.Reply()
    switch request.Code {
    case radius.AccessRequest:
        // check username and password
        if request.GetUsername() == "a" && request.GetPassword() == "a" {
            npac.Code = radius.AccessAccept
            return npac
        } else {
            npac.Code = radius.AccessReject
            npac.AVPs = append(npac.AVPs, radius.AVP{Type: radius.ReplyMessage, Value: []byte("you dick!")})
            return npac
        }
    case radius.AccountingRequest:
        // accounting start or end
        npac.Code = radius.AccountingResponse
        return npac
    default:
        npac.Code = radius.AccessAccept
        return npac
    }
}

func main() {
    s := radius.NewServer(":1812", "secret", radiusService{})

    // or you can convert it to a server that accept request 
    // from some host with different secret
    // cls := radius.NewClientList([]radius.Client{
    //      radius.NewClient("127.0.0.1", "secret1"),
    //      radius.NewClient("10.10.10.10", "secret2"),
    // })
    // s.WithClientList(cls)

    signalChan := make(chan os.Signal, 1)
    signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
    errChan := make(chan error)
    go func() {
        fmt.Println("waiting for packets...")
        err := s.ListenAndServe()
        if err != nil {
            errChan <- err
        }
    }()
    select {
    case <-signalChan:
        log.Println("stopping server...")
        s.Stop()
    case err := <-errChan:
        log.Println("[ERR] %v", err.Error())
    }
}