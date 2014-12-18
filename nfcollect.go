package main

import (
    "flag"
    "fmt"
    "log"
    "net"
    "time"
    "bytes"
    "encoding/binary"
    "encoding/json"
)

type Header struct {
    Version uint16 `json:"version"`
    FlowRecords uint16 `json:"flow_records"`
    Uptime uint32 `json:"uptime"`
    UnixSec uint32 `json:"unix_sec"`
    UnixNsec uint32 `json:"unix_nsec"`
    FlowSeqNum uint32 `json:"flow_seq_num"`
    EngineType uint8 `json:"engine_type"`
    EngineId uint8 `json:"engine_id"`
    SamplingInterval uint16 `json:"sampling_interval"`

}

type RecordBase struct {
    InputSnmp uint16 `json:"input_snmp"`
    OutputSnmp uint16 `json:"output_snmp"`
    InPkts uint32 `json:"in_pkts"`
    InBytes uint32 `json:"in_bytes"`
    FirstSwitched uint32 `json:"first_switched"`
    LastSwitched uint32 `json:"last_switched"`
    L4SrcPort uint16 `json:"l4_src_port"`
    L4DstPort uint16 `json:"l4_dst_port"`
    _ uint8
    TcpFlags uint8 `json:"tcp_flags"`
    Protocol uint8 `json:"protocol"`
    SrcTos uint8 `json:"src_tos"`
    SrcAs uint16 `json:"src_as"`
    DstAs uint16 `json:"dst_as"`
    SrcMask uint8 `json:"src_mask"`
    DstMask uint8 `json:"dst_mask"`
    _ uint16
}

type BinaryRecord struct {
    Ipv4SrcAddrInt uint32 `json:"-"`
    Ipv4DstAddrInt uint32 `json:"-"`
    Ipv4NextHopInt uint32 `json:"-"`

    RecordBase
}

type DecodedRecord struct {
    Header
    BinaryRecord

    Host string `json:"host"`
    SamplingAlgorithm uint8 `json:"sampling_algorithm"`
    Ipv4SrcAddr string `json:"ipv4_src_addr"`
    Ipv4DstAddr string `json:"ipv4_dst_addr"`
    Ipv4NextHop string `json:"ipv4_next_hop"`
}

func intToIPv4Addr(intAddr uint32) net.IP {
    return net.IPv4(
        byte(intAddr >> 24),
        byte(intAddr >> 16),
        byte(intAddr >> 8),
        byte(intAddr))
} 

func decodeRecord(header *Header, binRecord *BinaryRecord, remoteAddr *net.UDPAddr) DecodedRecord {
    decodedRecord := DecodedRecord{

        Host: remoteAddr.IP.String(),

        Header: *header,

        BinaryRecord: *binRecord,

        Ipv4SrcAddr: intToIPv4Addr(binRecord.Ipv4SrcAddrInt).String(),
        Ipv4DstAddr: intToIPv4Addr(binRecord.Ipv4DstAddrInt).String(),
        Ipv4NextHop: intToIPv4Addr(binRecord.Ipv4NextHopInt).String(),
    }

    // Modify sampling settings
    decodedRecord.SamplingAlgorithm = uint8(0x3 & (decodedRecord.SamplingInterval >> 14))
    decodedRecord.SamplingInterval = 0xc & decodedRecord.SamplingInterval

    return decodedRecord
}

func pipeOutputToStdout(outputChannel chan DecodedRecord) {
    var record DecodedRecord
    for {
        record = <- outputChannel

        go func (record DecodedRecord) {
            buf, err := json.Marshal(record)
            if err != nil {
                log.Fatalf("json.Marshal failed: %v\n", err)
            }

            fmt.Printf("%v\n", string(buf))
        }(record)
    }
}

func pipeOutputToUDPSocket(outputChannel chan DecodedRecord, targetAddr string) {
    /* Setting-up the socket to send data */
    remote, err := net.ResolveUDPAddr("udp", targetAddr)
    if err != nil {
        log.Fatalf("Name resolution failed: %v\n", err)
    }

    conn, err := net.DialUDP("udp", nil, remote)
    if err != nil {
        log.Fatalf("Connection failed: %v\n", err)
    }

    defer conn.Close()

    var record DecodedRecord
    for {
        record = <- outputChannel

        go func (record DecodedRecord) {
            buf, err := json.Marshal(record)
            if err != nil {
                log.Fatalf("json.Marshal failed: %v\n", err)
            }

            conn.SetDeadline(time.Now().Add(3 * time.Second))
            _, err = conn.Write(buf)
            if err != nil {
                log.Fatalf("Send Error: %v\n", err)
            }
        }(record)
    }
}

func handlePacket(buf *bytes.Buffer, remoteAddr *net.UDPAddr, outputChannel chan DecodedRecord) {
    header := Header{}
    err := binary.Read(buf, binary.BigEndian, &header)
    if err != nil {
        log.Fatalf("Error:", err)
    }

    for i := 0; i < int(header.FlowRecords); i++ {
        record := BinaryRecord{}
        err := binary.Read(buf, binary.BigEndian, &record)
        if err != nil {
            log.Fatalf("binary.Read failed: %v\n", err)
        }

        decodedRecord := decodeRecord(&header, &record, remoteAddr)

        //go emitEvent(event)
        outputChannel <- decodedRecord
    }
}

func main() {
    /* Parse command-line arguments */
    var (
        inSource string
        outDestination string
        receiveBufferSizeBytes int
    )
    flag.StringVar(&inSource, "i", "0.0.0.0:2055", "Address and port to listen NetFlow packets")
    flag.StringVar(&outDestination, "o", "127.0.0.1:5160", "Address and port to send decoded data")
    flag.IntVar(&receiveBufferSizeBytes, "b", 212992, "Size of RxQueue, i.e. value for SO_RCVBUF in bytes")
    flag.Parse()

    /* Create output pipe */
    outputChannel := make(chan DecodedRecord, 100)
    if outDestination == "-" {
        go pipeOutputToStdout(outputChannel)
    } else {
        go pipeOutputToUDPSocket(outputChannel, outDestination)
    }

    /* Start listerning on the specified port */
    log.Printf("Start listening on %v\n", inSource)
    addr, err := net.ResolveUDPAddr("udp", inSource)
    if err != nil {
        log.Fatalf("Error: %v\n", err)
    }
    conn, err := net.ListenUDP("udp", addr)
    if err != nil {
        log.Fatalln(err)
    }
    err = conn.SetReadBuffer(receiveBufferSizeBytes)
    if err != nil {
        log.Fatalln(err)
    }


    defer conn.Close()

    /* Infinite-loop for reading packets */
    for {
        buf := make([]byte, 4096)
        rlen, remote, err := conn.ReadFromUDP(buf)

        if err != nil {
            log.Fatalf("Error: %v\n", err)
        }

        stream := bytes.NewBuffer(buf[:rlen])
        
        go handlePacket(stream, remote, outputChannel)
    }
}
